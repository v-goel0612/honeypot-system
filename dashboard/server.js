require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const authMiddleware = require("./middleware/authMiddleware");
const authRoutes = require("./routes/auth");
const apiRoutes = require("./routes/api");

const app = express();
app.set("view engine", "ejs");
app.set("views", "./views");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

app.use("/", authRoutes);
app.use("/api", apiRoutes);

app.get("/dashboard", authMiddleware, (req, res) => {
  res.render("dashboard", { user: req.user });
});

app.get("/", (req, res) => res.redirect("/dashboard"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Dashboard running at http://localhost:${PORT}`));