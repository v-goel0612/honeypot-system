const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

router.get("/login", (req, res) => {
  res.render("login", { error: null });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const isUser = username === process.env.ADMIN_USERNAME;
  const isPass = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);

  if (!isUser || !isPass) {
    return res.render("login", { error: "Invalid credentials." });
  }

  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "8h" });
  res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
  res.redirect("/dashboard");
});

router.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

module.exports = router;