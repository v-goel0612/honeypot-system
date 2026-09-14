const express = require("express");
const router = express.Router();
const axios = require("axios");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const authMiddleware = require("../middleware/authMiddleware");

const HP_URL = process.env.HONEYPOT_API_URL;
const HP_KEY = process.env.HONEYPOT_API_KEY;
const headers = { "X-API-Key": HP_KEY };
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

router.get("/stats", authMiddleware, async (req, res) => {
  try {
    const { data } = await axios.get(`${HP_URL}/api/stats`, { headers });
    res.json(data);
  } catch { res.status(500).json({ error: "Failed to fetch stats" }); }
});

router.get("/attacks", authMiddleware, async (req, res) => {
  try {
    const { data } = await axios.get(`${HP_URL}/api/attacks`, { headers });
    res.json(data);
  } catch { res.status(500).json({ error: "Failed to fetch attacks" }); }
});

router.post("/ai-analysis", authMiddleware, async (req, res) => {
  try {
    const { stats, attacks } = req.body;
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = `You are a cybersecurity analyst. Analyze this honeypot attack data and provide a brief threat intelligence report.

Stats: ${JSON.stringify(stats)}
Recent attacks: ${JSON.stringify(attacks)}

Provide:
1. Overall threat assessment
2. Most dangerous IPs and why
3. Attack patterns you notice
4. Recommended defensive actions

Keep it under 200 words, plain text no markdown.`;

    const result = await model.generateContent(prompt);
    const text = result.response.text();
    res.json({ analysis: text });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
