import qrcode from "qrcode-terminal";
import pkg from "whatsapp-web.js";
import express from "express";
import path from "path";
import http from "http";
import { Server } from "socket.io";
import { fileURLToPath } from "url";
import { User } from "./models/User.js";
import { Login } from "./models/Login.js";
import mongoose from "mongoose";
import fetch from "node-fetch";
import session from "express-session";
import MongoStore from "connect-mongo";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import axios from "axios";
 

mongoose
  .connect(
    "mongodb+srv://bapasjakpuswebsite:FirdaAmalia2019!@cluster0.9vzsvra.mongodb.net/DevWhatsappClientManager",
    {}
  )
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((err) => console.error("MongoDB connection error:", err));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const downloadsDir = path.join(__dirname, "downloads");
if (!fs.existsSync(downloadsDir)) {
  fs.mkdirSync(downloadsDir);
}

const { Client, MessageMedia, LocalAuth } = pkg;

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
  transports: ["websocket", "polling"],
});

app.use(
  session({
    secret: "kucing",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl:
        "mongodb+srv://bapasjakpuswebsite:FirdaAmalia2019!@cluster0.9vzsvra.mongodb.net/whatsappClientManager",
    }),
    cookie: { maxAge: 180 * 60 * 1000 },
  })
);
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("public"));

const clients = {};

async function initializeClient(userType) {
  const client = new Client({
    authStrategy: new LocalAuth({
      clientId: userType,
      dataPath: path.join(__dirname, "sessions"),
    }),
    puppeteer: {
      headless: "new",
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-accelerated-2d-canvas",
        "--disable-gpu",
        "--no-zygote",
        "--disable-notifications",
        "--disable-extensions",
        "--mute-audio",
        "--disable-default-apps",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--disable-infobars",
        "--autoplay-policy=user-gesture-required",
        "--window-size=1024,768",
      ],
    },
  });

  let qrCodeEnabled = false;
  let qrTimeout = null;

  client.on("qr", (qr) => {
    if (qrCodeEnabled) {
      qrcode.generate(qr, { small: true });
      io.emit("qr", { userType, qr });
      qrTimeout = setTimeout(() => {
        console.log(`QR code for client ${userType} has expired.`);
        io.emit("qrExpired", { userType });
        client.destroy();
      }, 70000);
    }
  });

  qrCodeEnabled = true;

  client.on("ready", async () => {
    console.log(`Client ${userType} is ready!`);
    clearTimeout(qrTimeout);
    const userNumber = client.info.wid.user;
    const timestamp = new Date().toLocaleString();

    const existingUser = await User.findOne({ userType: userType });

    if (!existingUser) {
      await User.updateOne(
        { number: userNumber },
        {
          number: userNumber,
          time: timestamp,
          status: "online",
          userType: userType,
        },
        { upsert: true }
      );
    }

    io.emit("userLoggedIn", { number: userNumber, time: timestamp });
  });

  client.on("disconnected", async (reason) => {
    console.log(`Client ${userType} was logged out:`, reason);
    let userNumber;
    try {
      userNumber = client.info.wid.user;
      console.log("User number:", userNumber);
      if (!userNumber) {
        throw new Error("User number is undefined");
      }
    } catch (error) {
      console.error("Error retrieving user number:", error.message);
      userNumber = null;
    }

    try {
      const clientRecord = await User.findOne({ userType: userType });
      if (clientRecord) {
        await clientRecord.deleteOne();
      } else {
        console.warn(`No client found for number: ${userType}`);
      }
    } catch (dbError) {
      console.error("Database error:", dbError.message);
    }
    if (userNumber) {
      io.emit("userDisconnected", { number: userNumber });
    } else {
      console.warn("User number is not available, skipping emit.");
    }

    qrCodeEnabled = false;
    if (clients[userType]) {
      delete clients[userType];
      console.log(`Client ${userNumber} removed from clients object.`);
    } else {
      console.warn(
        `Client with user type ${userType} not found in clients object.`
      );
    }
  });

  client.on("authenticated", async () => {
    console.log(`Client ${userType} authenticated!`);
  });
  client.on("auth_failure", (message) => {
    console.error(`Authentication failure for client ${userType}:`, message);
  });

  let userSessions = {};
  const sessionTimeout = 1 * 60 * 1000; // 5 minutes

  client.on("message_create", async (message) => {
    if (message.from === client.info.wid._serialized) {
        return;
    }

    const sender_original = message.from;
    const currentUser = message.to;
    const formattedCurrentUser = currentUser.split("@")[0];
    const sender = sender_original.split("@")[0];
    const wa_client = await User.findOne({ number: formattedCurrentUser });
    const userMessage = message.body.trim();
    const webhookUrl = wa_client ? wa_client.webhookUrl : null;          
    const timestamp = new Date().toLocaleString();
    const chat = message.getChat();

    if (message.type === "chat" && message.type !== "location" && sender_original !== "status@broadcast") {
        if (message.body === "ping") {
            client.sendMessage(sender_original, "pong");
        }

        if (message.body === "klien aktif") {
            const activeClients = Object.keys(clients);
            client.sendMessage(sender_original, `Active clients: ${activeClients.join(", ")}`);
        }

        if (!webhookUrl) {
            console.log("Pesan Chat. Webhook URL is not set for this client.");
            return;
        }

        if (userMessage === ".start") {
             (await chat).sendStateTyping()      
          
            userSessions[sender_original] = {
                active: true,
                lastActive: Date.now(),
                timeout: null,
            };
            message.reply("Halo, ada yang bisa saya bantu?");
            return;
        }

        if (userMessage === ".exit") {
          (await chat).sendStateTyping()      
            if (userSessions[sender_original] && userSessions[sender_original].timeout) {
                clearTimeout(userSessions[sender_original].timeout);
            }

            delete userSessions[sender_original];
            message.reply("Terima kasih, jika ada yang ingin ditanyakan kembali, silahkan ketik .start.");
            return;
        }

        if (userSessions[sender_original]) {

            if (webhookUrl.includes("smartChat")) {
              (await chat).sendStateTyping()            
              if (userSessions[sender_original].timeout) {
                  clearTimeout(userSessions[sender_original].timeout);
              }               
              userSessions[sender_original].lastActive = Date.now();

              const gptResponse = await getChatGPTResponse(userMessage);           
              message.reply(gptResponse);       
       
                } else if(!webhookUrl.includes("smartChat")) {   
                  (await chat).sendStateTyping()              
                  if (userSessions[sender_original].timeout) {
                      clearTimeout(userSessions[sender_original].timeout);
                  }
                  userSessions[sender_original].lastActive = Date.now();
                                    
                        const database = await fetchDataBase(webhookUrl);
                        if (userMessage.length > 150) {
                            message.reply("Pesanmu melebihi batas 150 karakter. Silahkan pendekkan pesanmu dan coba lagi.");
                            return;
                        }            
                        const botResponse = await getOpenAIResponse(userMessage, database);
                        message.reply(botResponse);          
                                    
                }

                userSessions[sender_original].timeout = setTimeout(() => {
                  if (userSessions[sender_original]) {
                      delete userSessions[sender_original];
                      client.sendMessage(sender_original, "Terima kasih telah menghubungi kami, sesi percakapan telah berakhir. Silahkan ketik .start jika ingin memulai kembali percakapan.");
                  }
              }, sessionTimeout);
     
        } else {
          if (wa_client && wa_client.webhookUrl) {
            try {
                await fetch(wa_client.webhookUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        timestamp,
                        sender,
                        message: message.body,
                    }),
                });                    
                console.log("Message data sent to webhook successfully.");
            } catch (error) {
                console.error("Error processing message, Format webhook bukan pesan");
            }
        }
          
        } //bracket sesi
           
        
    } else if (message.type !== "chat" && message.type === "location" && sender_original !== "status@broadcast") {
        const { latitude, longitude, url, name } = message.location || {};
    
        (await chat).sendStateTyping()

        if (wa_client && wa_client.webhookUrl) {
            try {
                await fetch(wa_client.webhookUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        sender,
                        latitude,
                        longitude,
                        url,
                        name,
                    }),
                });

                console.log("Location data sent to webhook successfully.");
                const response = await fetch(`${wa_client.webhookUrl}?query=${sender}`);
                const data = await response.json();
                console.log("Response from webhook:", data.response);

           
                if (data.response) {
                    const reply = data.response.replace(/\\n/g, "\n"); 
                    
           
                    client.sendMessage(sender_original, reply);
                    
                }
            } catch (error) {
                console.error("Format webhook bukan lokasi.");
            }
        }
    }
});

  await client.initialize();
  clients[userType] = client;
}

app.post("/initializeClient", async (req, res) => {
  const { username, password, userType } = req.body;

  const user = await Login.findOne({ username });
  if (!user || user.password !== password) {
    return res.status(401).send({ error: "Invalid username or password." });
  }

  const existingUser = await User.findOne({ userType: user.userType });

  if (existingUser) {
    return res.status(400).send({
      error: `Tidak bisa menambahkan koneksi device untuk username ${user.userType}. Hapus dulu device yang sudah ada. `,
    });
  }

  await initializeClient(userType);
  res.status(200).send({
    result: `Device dengan username ${userType} telah terkoneksi.`,
  });
});

app.post("/reInitializeClient", async (req, res) => {
  const { username, password, userType } = req.body;

  const user = await Login.findOne({ username });
  if (!user || user.password !== password) {
    return res.status(401).send({ error: "Invalid username or password." });
  }

  await initializeClient(userType);
  res.status(200).send({
    result: `Device dengan username ${userType} telah terkoneksi.`,
  });
});

app.post("/sendMessage", async (req, res) => {
  const { sender, to, message } = req.body;

  if (!sender || !to || !message) {
    return res
      .status(400)
      .send({ error: "Sender, recipient, and message are required." });
  }

  console.log("Sender:", sender, "Recipient:", to, "Message:", message);

  const client = clients[sender];

  if (!client) {
    console.log("Client not found for sender:", sender);
    return res.status(404).send({ error: "Sender number not found." });
  }

  let formattedRecipient;

  if (to.includes("@g.us")) {
    formattedRecipient = to;
  } else if (!to.includes("@g.us")) {
    formattedRecipient = `${to}@c.us`;
  } else {
    return res.status(400).send({ error: "Invalid recipient format." });
  }

  try {
    await client.sendMessage(formattedRecipient, message);
    res.status(200).send({ result: "Message sent successfully." });
  } catch (error) {
    console.error("Error sending message:", JSON.stringify(error, null, 2));
    res.status(500).send({ error: "Failed to send message." });
  }
});

app.post("/sendMedia", async (req, res) => {
  const { sender, to, message, name, captions } = req.body;

  if (!sender || !to || !message) {
    return res
      .status(400)
      .send({ error: "Sender, recipient, and message are required." });
  }

  console.log("Sender:", sender, "Recipient:", to, "Message:", message);

  const client = clients[sender]; // Access client using sender as key

  if (!client) {
    console.log("Client not found for sender:", sender);
    return res
      .status(404)
      .send({ error: "Tidak ada nomor pengirim tidak ditemukan." });
  }

  let formattedRecipient;

  // Replacing startsWith with includes
  if (to.includes("@g.us")) {
    formattedRecipient = to;
  } else if (!to.includes("@g.us")) {
    formattedRecipient = `${to}@c.us`;
  } else {
    return res.status(400).send({ error: "Invalid recipient format." });
  }

  try {
    const media = await MessageMedia.fromUrl(message, { filename: name });
    await client.sendMessage(formattedRecipient, media, {
      caption: captions,
    });

    res.status(200).send({ result: "Message sent successfully." });
  } catch (error) {
    console.error("Error sending message:", JSON.stringify(error, null, 2));
    res.status(500).send({ error: "Failed to send message." });
  }
});

app.post("/sendDrivePdf", async (req, res) => {
  const { sender, to, document, name, captions } = req.body;

  if (!sender || !to) {
    return res
      .status(400)
      .send({ error: "Sender, recipient, and message are required." });
  }

  console.log("Sender:", sender, "Recipient:", to, "Message:", document);

  const client = clients[sender]; // Access client using sender as key

  if (!client) {
    console.log("Client not found for sender:", sender);
    return res
      .status(404)
      .send({ error: "Tidak ada nomor pengirim tidak ditemukan." });
  }

  let formattedRecipient;

  // Replacing startsWith with includes
  if (to.includes("@g.us")) {
    formattedRecipient = to;
  } else if (!to.includes("@g.us")) {
    formattedRecipient = `${to}@c.us`;
  } else {
    return res.status(400).send({ error: "Invalid recipient format." });
  }

  try {
    const localFilePath = path.join(downloadsDir, "document.pdf");
    const response = await fetch(document);
    const pdfBuffer = await response.buffer();

    fs.writeFileSync(localFilePath, pdfBuffer);
    console.log("PDF downloaded and saved locally.");

    const file = new MessageMedia(
      "application/pdf",
      pdfBuffer.toString("base64"),
      name
    );

    await client.sendMessage(formattedRecipient, file, { caption: captions });

    res.status(200).send({ result: "Message sent successfully." });
  } catch (error) {
    console.error("Error sending message:", JSON.stringify(error, null, 2));
    res.status(500).send({ error: "Failed to send message." });
  }
});

app.post("/sendDriveImage", async (req, res) => {
  const { sender, to, imageUrl, name, captions } = req.body;

  if (!sender || !to) {
    return res
      .status(400)
      .send({ error: "Sender and recipient are required." });
  }

  console.log("Sender:", sender, "Recipient:", to, "Image URL:", imageUrl);

  const client = clients[sender]; // Access client using sender as key

  if (!client) {
    console.log("Client not found for sender:", sender);
    return res.status(404).send({ error: "Sender not found." });
  }

  let formattedRecipient;
  // Replacing startsWith with includes
  if (to.includes("@g.us")) {
    formattedRecipient = to;
  } else if (!to.includes("@g.us")) {
    formattedRecipient = `${to}@c.us`;
  } else {
    return res.status(400).send({ error: "Invalid recipient format." });
  }

  console.log("Formatted Recipient:", formattedRecipient);

  try {
    const localFilePath = path.join(downloadsDir, "image.jpg"); // Change the file extension as needed
    const response = await fetch(imageUrl);

    if (!response.ok) {
      throw new Error("Failed to fetch image from the provided URL.");
    }

    const imageBuffer = await response.buffer();
    fs.writeFileSync(localFilePath, imageBuffer);
    console.log("Image downloaded and saved locally.");

    const file = new MessageMedia(
      "image/jpeg",
      imageBuffer.toString("base64"),
      name
    );

    await client.sendMessage(formattedRecipient, file, { caption: captions });

    res.status(200).send({ result: "Image sent successfully." });
  } catch (error) {
    console.error("Error sending message:", JSON.stringify(error, null, 2));
    res.status(500).send({ error: "Failed to send image." });
  }
});

app.get("/group-details/:clientNumber", async (req, res) => {
  const { clientNumber } = req.params;
  const client = clients[clientNumber]; // Access client using clientNumber as key

  if (!client) {
    return res.status(404).json({ error: "Client not found" });
  }

  const groups = await client.getChats();
  const groupDetails = groups
    .filter((chat) => chat.isGroup)
    .map((group) => ({
      id: group.id._serialized,
      name: group.name,
    }));

  res.json(groupDetails);
});

async function deleteAllClients() {
  try {
    const result = await User.deleteMany({});

    if (result.deletedCount === 0) {
      console.log("No clients found to delete.");
    } else {
      console.log("All clients have been successfully deleted.");
    }
  } catch (error) {
    console.error("Error deleting all clients:", error);
  }
}

app.post("/updateWebhook", async (req, res) => {
  const { clientNumber, webhookUrl } = req.body;

  try {
    await User.updateOne(
      { number: clientNumber },
      { webhookUrl: webhookUrl }, // Update webhook URL
      { upsert: true }
    );
    res.status(200).send({
      result: `Webhook URL telah diperbaharui untuk nomor ${clientNumber}`,
    });
  } catch (error) {
    console.error(`Error updating webhook: ${error.message}`);
    res
      .status(500)
      .send({ error: "Gagal memperbaharui webhook URL. Mohon coba lagi." });
  }
});

app.post("/updateJenisPesan", async (req, res) => {
  const { clientNumber, jenisPesan } = req.body;

  try {
    await User.updateOne(
      { number: clientNumber },
      { jenisPesan: jenisPesan }, // Update webhook URL
      { upsert: true }
    );
    res.status(200).send({
      result: `Jenis Pesan telah diperbaharui untuk nomor ${clientNumber}`,
    });
  } catch (error) {
    console.error(`Error updating webhook: ${error.message}`);
    res
      .status(500)
      .send({ error: "Gagal memperbaharui Jenis Pesan. Mohon coba lagi." });
  }
});

app.post("/updateSheetUrl", async (req, res) => {
  const { clientNumber, sheetUrl } = req.body;

  try {
    await User.updateOne(
      { number: clientNumber },
      { sheetUrl: sheetUrl },
      { upsert: true }
    );
    res.status(200).send({
      result: `Sheet URL telah diperbaharui untuk nomor ${clientNumber}`,
    });
  } catch (error) {
    console.error(`Error updating sheetUrl: ${error.message}`);
    res
      .status(500)
      .send({ error: "Gagal memperbaharui Sheet URL. Mohon coba lagi." });
  }
});

app.get("/clients", async (req, res) => {
  try {
    const clients = await User.find({});
    res.status(200).send(clients);
  } catch (error) {
    console.error("Error retrieving clients:", error);
    res.status(500).send({ error: "Failed to retrieve clients" });
  }
});

app.post("/logout/:userType", async (req, res) => {
  const { userType } = req.params;

  try {
    const client = await User.findOne({ userType: userType });

    if (!client) {
      return res.status(404).send({ error: "Nomor tidak ditemukan." });
    }

    await client.updateOne({ status: "offline" });
    const clientInstance = clients[userType];
    if (clientInstance) {
      await clientInstance.destroy();
      console.log(`Client ${userType} logged out successfully.`);
      delete clients[userType];
      console.log(`Client ${userType} removed from clients object.`);
    }
    io.emit("userDisconnected", { userType: userType });
    res.status(200).send({ result: `Nomor ${userType} berhasil logout.` });
  } catch (error) {
    console.error(`Error logging out client ${userType}:`, error);
    res.status(500).send({ error: "Logout gagal." });
  }
});

app.delete("/deleteClient/:clientNumber", async (req, res) => {
  const { clientNumber } = req.params;

  try {
    const client = await User.findOne({ number: clientNumber });

    if (!client) {
      return res.status(404).send({ error: "Client not found." });
    }

    await client.deleteOne();
    res.status(200).send({ result: `Nomor ${clientNumber} berhasil dihapus.` });
  } catch (error) {
    console.error(`Error deleting client ${clientNumber}:`, error);
    res.status(500).send({ error: "Gagal menghapus." });
  }
});

app.get("/sendMessagePage", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "tesPesan.html"));
});

app.get("/users", async (req, res) => {
  try {
    const users = await Login.find({}); // Exclude password from the response
    res.status(200).send(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send({ message: "Failed to fetch users." });
  }
});

app.put("/edit/:username", async (req, res) => {
  const { username } = req.params;
  const { username: newUsername, password } = req.body;

  try {
    // Directly update the password without hashing
    await Login.updateOne({ username }, { username: newUsername, password });
    res.status(200).send({ message: "User updated successfully!" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send({ message: "Failed to update user." });
  }
});

app.delete("/delete/:username", async (req, res) => {
  const { username } = req.params;

  try {
    await Login.deleteOne({ username });
    res.status(200).send({ message: "User deleted successfully!" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send({ message: "Failed to delete user." });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await Login.findOne({ username });
    if (!user || user.password !== password) {
      return res.status(401).send({ message: "Invalid username or password." });
    }

    req.session.username = username; // Store username in session
    req.session.userType = user.userType; // Store user type in session
    res.status(200).send({ success: true, message: "Login successful!" });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).send({ message: "Login failed. Please try again." });
  }
});

function isAuthenticated(req, res, next) {
  if (req.session && req.session.username) {
    return next();
  }
  res
    .status(403)
    .send({ message: "Forbidden: You need to log in to access this page." });
}

function isAuthorized(userType) {
  return (req, res, next) => {
    if (userType.includes(req.session.userType)) {
      return next();
    }
    res
      .status(403)
      .send({ message: "Forbidden: You do not have access to this page." });
  };
}

app.get("/admin.html", isAuthenticated, isAuthorized("admin"), (req, res) => {
  res.sendFile(path.join(__dirname, "protected", "admin.html"));
});

app.get("/users.html", isAuthenticated, isAuthorized("admin"), (req, res) => {
  res.sendFile(path.join(__dirname, "protected", "users.html"));
});

app.get("/index.html", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "protected", "index.html"));
});

app.get("/register.html", (req, res) => {
  res.sendFile(path.join(__dirname, "protected", "register.html"));
});

app.get("/about.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "about.html"));
});

app.get("/contact.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "contact.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/register", async (req, res) => {
  const { username, password, userType } = req.body;

  try {
    // Directly save the plain password without hashing
    const newUser = new Login({ username, password, userType });
    await newUser.save();
    res.status(201).send({
      message: "User registered successfully!",
      user: { username, userType }, // Return user info
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).send({ message: "Registration failed. Please try again." });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .send({ message: "Logout failed. Please try again." });
    }
    res.status(200).send({ message: "Logout successful." });
  });
});

app.get("/checkSession", (req, res) => {
  if (req.session.username) {
    res
      .status(200)
      .send({ message: `Session active for user: ${req.session.username}` });
  } else {
    res.status(401).send({ message: "No active session." });
  }
});

const PORT = process.env.PORT || 9000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.get("/userType", (req, res) => {
  if (req.session && req.session.userType) {
    res.status(200).send({ userType: req.session.userType });
  } else {
    res.status(403).send({ error: "User type not found." });
  }
});

async function fetchDataBase(apiUrl) {
  try {
    const response = await axios.get(`${apiUrl}?query=data_chatbot`);
    return response.data;
  } catch (error) {
    console.error("Error fetching data: URL tidak ada atau tidak valid");
    return {};
  }
}

async function getOpenAIResponse(userMessage, database) {
  const prompt = `Based on the following data: ${JSON.stringify(
    database
  )}, respond to the user query: "${userMessage}" in Indonesian`;

  try {
    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 500,
      },
      {
        headers: {
          Authorization: `Bearer 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`,
          "Content-Type": "application/json",
        },
      }
    );

    return response.data.choices[0].message.content;
  } catch (error) {
    console.error("Error fetching response from OpenAI:", error);
    return "Sorry, I couldn't process your request.";
  }
}

async function getChatGPTResponse(userInput) {
  const response = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: userInput }],
      max_tokens: 500,
    },
    {
      headers: {
        Authorization: `Bearer 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`,
        "Content-Type": "application/json",
      },
    }
  );
  return response.data.choices[0].message.content;
}
