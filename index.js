require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3001;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

app.use(express.json());
app.use(cors());

// Models
const User = require("./models/User");

// Open Route - Public Route
app.get("/", (req, res) => {
  res.send("OPA, BÃO");
});

// Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // Vadidations
  if (!name) {
    return res.status(422).json({
      message: "O nome é obrigatório!",
    });
  }

  if (!email) {
    return res.status(422).json({
      message: "O email é obrigatório!",
    });
  }

  if (!password) {
    return res.status(422).json({
      message: "A senha é obrigatória!",
    });
  }

  if (!confirmPassword) {
    return res.status(422).json({
      message: "Confirme sua senha!",
    });
  }

  if (password !== confirmPassword) {
    return res.status(422).json({
      message: "As senhas precisam ser a mesma!",
    });
  }

  // User exists
  const userExist = await User.findOne({
    email: email,
  });

  if (userExist) {
    return res.status(422).json({
      message: "Email já existe!",
    });
  }

  // Create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({
      message: "Usuário criado com sucesso!",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Ouve algum erro no servidor. Tente mais tarde.",
    });
  }
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // If user Exist
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({
      message: "Usuário não encontrado.",
    });
  }

  res.json(user);
});

// Check token
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Acesso negado.",
    });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (err) {
    console.log(err);
    res.status(400).json({
      message: "Token inválido",
    });
  }
}

// Login User
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validations
  if (!email) {
    return res.status(422).json({
      message: "Email ausente!",
    });
  }

  if (!password) {
    return res.status(422).json({
      message: "Senha ausente!",
    });
  }

  // Check if user exist
  const user = await User.findOne({
    email: email,
  });

  if (!user) {
    return res.status(422).json({
      message: "Usuário ou senha incorreto!",
    });
  }

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({
      message: "Usuário ou senha incorreto!",
    });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({
      message: "Autenticação realizado com sucesso!",
      token,
    });
  } catch (err) {
    res.status(500).json({
      message: "Não foi possivel fazer o login!",
    });
  }
});

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@authjwt.vcr8m.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(PORT, () => {
      console.log("API conectada.");
    });
    console.log("Banco de dados conectado.");
  })
  .catch((err) => console.log(err));
