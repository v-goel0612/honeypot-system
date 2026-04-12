const express = require("express");
const router = express.Router();
const axios = require("axios");
const authMiddleware = require("../middleware/authMiddleware");

const HP_URL = process.env.HONEYPOT_API_URL;
const HP_KEY = process.env.HONEYPOT_API_KEY;
const headers = { "X-API-Key": HP_KEY };

router.get("/stats", authMiddleware, async (req, res) => {
  try {
    const { data } = await axios.get(`${HP_URL}/api/stats`, { headers });
    res.json(data);
  } catch {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

router.get("/attacks", authMiddleware, async (req, res) => {
  try {
    const { data } = await axios.get(`${HP_URL}/api/attacks`, { headers });
    res.json(data);
  } catch {
    res.status(500).json({ error: "Failed to fetch attacks" });
  }
});

module.exports = router;