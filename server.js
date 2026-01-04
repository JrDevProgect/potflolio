import express from "express";
import path from "path";
import { readFile, writeFile } from "fs/promises";
import { fileURLToPath } from "url";
import cors from "cors";
import crypto from "crypto";
import session from "express-session";
import axios from "axios";
import multer from "multer";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "seanwillbert";

const ADMIN_HASH = crypto
  .createHash("sha256")
  .update(ADMIN_PASSWORD)
  .digest("hex");

let config = {
  clientName: "Default Client",
  facebookLink: "",
  contactEmail: "",
  facebookPosts: [],
  proofItems: [],
};

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "seanwillbert",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "proof-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

const authenticateAdmin = (req, res, next) => {
  if (req.session && req.session.admin) {
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
};

const loadConfig = async () => {
  try {
    const configPath = path.join(__dirname, "config.json");
    const data = await readFile(configPath, "utf-8");
    const savedConfig = JSON.parse(data);
    config = { ...config, ...savedConfig };
  } catch (error) {
    await saveConfig();
  }
};

const saveConfig = async () => {
  try {
    await writeFile(
      path.join(__dirname, "config.json"),
      JSON.stringify(config, null, 2),
      "utf-8"
    );
  } catch (error) {}
};

const resolveFacebookLink = async (url) => {
  try {
    const response = await axios.get(url, {
      headers: {
        accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        pragma: "no-cache",
        priority: "u=0, i",
        "sec-ch-ua":
          '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
      maxRedirects: 10,
      validateStatus: null,
      timeout: 15000,
    });

    let finalUrl = response.request.res.responseUrl || response.config.url;

    const postUrlMatch = finalUrl.match(
      /(https:\/\/www\.facebook\.com\/[^\/]+\/(?:posts|photos|videos|permalink|reel)\/(?:pfbid\w+|[\w-]+))(\?|$)/
    );

    if (postUrlMatch) {
      return postUrlMatch[1];
    } else {
      return finalUrl;
    }
  } catch (error) {
    if (error.response) {
    }
    throw new Error("Invalid or inaccessible Facebook link");
  }
};

app.get("/api/config", (req, res) => {
  res.json({
    clientName: config.clientName,
    facebookLink: config.facebookLink,
    contactEmail: config.contactEmail,
    facebookPosts: config.facebookPosts,
    proofItems: config.proofItems,
  });
});

app.get("/admin/login", (req, res) => {
  res.render("login", { error: req.session.loginError || null });
});

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === ADMIN_USERNAME &&
    crypto.createHash("sha256").update(password).digest("hex") === ADMIN_HASH
  ) {
    req.session.admin = true;
    req.session.loginError = null;
    res.redirect("/admin");
  } else {
    req.session.loginError = "Invalid credentials";
    res.redirect("/admin/login");
  }
});

app.post("/admin/logout", (req, res) => {
  req.session.destroy((err) => {});
  res.redirect("/");
});

app.get("/admin", authenticateAdmin, (req, res) => {
  res.render("admin", { config });
});

app.get("/api/admin/config", authenticateAdmin, (req, res) => {
  res.json(config);
});

app.post("/api/admin/config", authenticateAdmin, async (req, res) => {
  try {
    if (
      typeof req.body.clientName !== "string" ||
      typeof req.body.contactEmail !== "string"
    ) {
      return res.status(400).json({ error: "Invalid data format" });
    }
    config = { ...config, ...req.body };
    await saveConfig();
    res.json({ success: true, message: "Configuration updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to save configuration" });
  }
});

app.post(
  "/api/admin/add-proof-item",
  authenticateAdmin,
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, testimonial } = req.body;

      if (!req.file) {
        return res.status(400).json({ error: "Image file is required" });
      }

      if (!title || !testimonial) {
        return res
          .status(400)
          .json({ error: "Missing required fields (title, testimonial)" });
      }

      const imageUrl = `/uploads/${req.file.filename}`;

      config.proofItems.push({ image: imageUrl, title, testimonial });
      await saveConfig();
      res.json({
        success: true,
        message: "Proof item added successfully",
        image: imageUrl,
      });
    } catch (error) {
      if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
          return res
            .status(400)
            .json({ error: "File too large. Maximum size is 5MB." });
        }
        if (error.code === "LIMIT_UNEXPECTED_FILE") {
          return res
            .status(400)
            .json({ error: "Unexpected field name for image upload." });
        }
      }
      res
        .status(500)
        .json({ error: error.message || "Failed to add proof item" });
    }
  }
);

app.post(
  "/api/admin/update-proof-item",
  authenticateAdmin,
  upload.single("image"),
  async (req, res) => {
    try {
      const { index, title, testimonial, oldImage } = req.body;

      if (index === undefined || !title || !testimonial) {
        return res.status(400).json({
          error: "Missing required fields (index, title, testimonial)",
        });
      }

      const itemIndex = parseInt(index);
      if (
        isNaN(itemIndex) ||
        itemIndex < 0 ||
        itemIndex >= config.proofItems.length
      ) {
        return res.status(400).json({ error: "Invalid index" });
      }

      let imageUrl = oldImage;
      if (req.file) {
        imageUrl = `/uploads/${req.file.filename}`;
      } else if (!oldImage) {
        return res.status(400).json({
          error: "Image file is required if no previous image exists.",
        });
      }

      config.proofItems[itemIndex] = { image: imageUrl, title, testimonial };
      await saveConfig();
      res.json({
        success: true,
        message: "Proof item updated successfully",
        image: imageUrl,
      });
    } catch (error) {
      if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
          return res
            .status(400)
            .json({ error: "File too large. Maximum size is 5MB." });
        }
        if (error.code === "LIMIT_UNEXPECTED_FILE") {
          return res
            .status(400)
            .json({ error: "Unexpected field name for image upload." });
        }
      }
      res
        .status(500)
        .json({ error: error.message || "Failed to update proof item" });
    }
  }
);

app.delete(
  "/api/admin/delete-proof-item/:index",
  authenticateAdmin,
  async (req, res) => {
    try {
      const index = parseInt(req.params.index);
      if (isNaN(index) || index < 0 || index >= config.proofItems.length) {
        return res.status(400).json({ error: "Invalid index" });
      }

      config.proofItems.splice(index, 1);
      await saveConfig();
      res.json({ success: true, message: "Proof item deleted successfully" });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete proof item" });
    }
  }
);

app.post(
  "/api/admin/add-facebook-post",
  authenticateAdmin,
  async (req, res) => {
    try {
      const { postUrl } = req.body;
      if (!postUrl)
        return res.status(400).json({ error: "Post URL is required" });

      const finalUrl = await resolveFacebookLink(postUrl);

      if (
        !finalUrl.includes("facebook.com/") ||
        (!finalUrl.includes("/posts/") &&
          !finalUrl.includes("/photos/") &&
          !finalUrl.includes("/videos/") &&
          !finalUrl.includes("/permalink/") &&
          !finalUrl.includes("/reel/"))
      ) {
        return res.status(400).json({
          error:
            "Resolved URL is not a valid Facebook post, photo, video, or permalink.",
        });
      }

      config.facebookPosts.push(finalUrl);
      await saveConfig();
      res.json({
        success: true,
        message: "Facebook post added successfully",
        finalUrl,
      });
    } catch (error) {
      res
        .status(500)
        .json({ error: error.message || "Failed to add Facebook post" });
    }
  }
);

app.post(
  "/api/admin/update-facebook-post",
  authenticateAdmin,
  async (req, res) => {
    try {
      const { index, postUrl } = req.body;
      if (index === undefined || !postUrl)
        return res.status(400).json({ error: "Missing required fields" });
      const urlIndex = parseInt(index);
      if (
        isNaN(urlIndex) ||
        urlIndex < 0 ||
        urlIndex >= config.facebookPosts.length
      ) {
        return res.status(400).json({ error: "Invalid index" });
      }

      const finalUrl = await resolveFacebookLink(postUrl);

      if (
        !finalUrl.includes("facebook.com/") ||
        (!finalUrl.includes("/posts/") &&
          !finalUrl.includes("/photos/") &&
          !finalUrl.includes("/videos/") &&
          !finalUrl.includes("/permalink/"))
      ) {
        return res.status(400).json({
          error:
            "Resolved URL is not a valid Facebook post, photo, video, reel, or permalink.",
        });
      }

      config.facebookPosts[urlIndex] = finalUrl;
      await saveConfig();
      res.json({
        success: true,
        message: "Facebook post updated successfully",
        finalUrl,
      });
    } catch (error) {
      res
        .status(500)
        .json({ error: error.message || "Failed to update Facebook post" });
    }
  }
);

app.delete(
  "/api/admin/delete-facebook-post/:index",
  authenticateAdmin,
  async (req, res) => {
    try {
      const index = parseInt(req.params.index);
      if (isNaN(index) || index < 0 || index >= config.facebookPosts.length) {
        return res.status(400).json({ error: "Invalid index" });
      }
      config.facebookPosts.splice(index, 1);
      await saveConfig();
      res.json({
        success: true,
        message: "Facebook post deleted successfully",
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete Facebook post" });
    }
  }
);

app.get("/", (req, res) => {
  res.render("index", { config });
});

app.get("*", (req, res) => {
  res.render("index", { config });
});

const startServer = async () => {
  await loadConfig();
  app.listen(PORT, () => {});
};

startServer().catch(console.error);
