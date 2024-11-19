import express from "express";
import cors from "cors";
import sequelize from "./config/db.js";
import bcrypt from "bcrypt";
import User from "./models/user.js";
import jwt from "jsonwebtoken";
import "dotenv/config";
import MustChangePasswordMiddleware from "./middleware/MustChangePasswordMiddleware.js";
import authorizeRoleMiddleware from "./middleware/authRoleMiddleware.js";
import logRequest from "./middleware/logRequest.js";
import authMiddleware from "./middleware/authMiddleware.js";

const app = express();
const PORT = process.env.PORT || "3000";
const jwtSecret = process.env.JWT_SECRET_KEY || "secret_key";

app.use(cors());
app.use(logRequest);
app.use(express.json());
app.use(MustChangePasswordMiddleware);

const handleError = (res, error, message = "Ошибка сервера.") => {
  console.error(message, error);
  return res.status(500).json({ error: message });
};

const userExists = async (email) => {
  return await User.findOne({ where: { email } });
};

app.get("/", (req, res) => {
  res.send("My Server");
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email и пароль обязательны." });
  }

  try {
    const existingUser = await User.findOne({ where: { email } });
    if (await userExists(email)) {
      return res.status(400).json({ error: "Email уже зарегистрирован." });
    }

    const hashedPassword = await bcrypt.hash(password, 5);
    await User.create({ email, password: hashedPassword });

    res.status(201).json({ message: "Пользователь успешно зарегистрирован." });
  } catch (error) {
    handleError(res, error, "Ошибка при регистрации.");
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await userExists(email);
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!user || !isPasswordValid) {
      return res.status(401).send("invalid data");
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      jwtSecret,
      {
        expiresIn: "1h",
      }
    );

    return res.json({
      name: user.name,
      role: user.role,
      token,
      message: "Пользователь успешно вошел в систему.",
    });
  } catch (error) {
    handleError(res, error, "Ошибка при входе.");
  }
});

app.put("/reset-password/:id", authMiddleware, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (req.user.id !== userId) {
      return res.status(403).send("Access denied");
    }

    const user = await User.findOne({ where: { id: userId } });
    if (!user) {
      return res.status(404).send("User  not found");
    }

    user.mustChangePassword = true;
    await user.save();
    res.send(
      "Пароль успешно сброшен. Пожалуйста, смените пароль при следующем входе."
    );
  } catch (error) {
    handleError(res, error, "Ошибка при сбросе пароля.");
  }
});

app.put("/change-role/:id", authMiddleware, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (req.user.id !== userId) {
      return res.status(403).send("Access denied");
    }

    const user = await User.findOne({ where: { id: userId } });
    if (!user) {
      return res.status(404).send("User  not found");
    }

    user.role = "admin";
    await user.save();
    res.send("Successful change role");
  } catch (error) {
    handleError(res, error, "Error change role");
  }
});

app.put("/change-password/:id", authMiddleware, async (req, res) => {
  const { newPassword } = req.body;
  const userId = Number(req.params.id);

  if (req.user.id !== userId) {
    return res.status(403).json({
      error: "У вас нет прав для изменения пароля этого пользователя.",
    });
  }

  if (!newPassword) {
    return res.status(400).json({
      error: "Новый пароль не может быть пустым.",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 5);

    await User.update(
      { password: hashedPassword, mustChangePassword: false },
      { where: { id: userId } }
    );

    res.status(200).json({ message: "Пароль успешно изменен." });
  } catch (error) {
    handleError(res, error, "Ошибка при изменении пароля.");
  }
});

app.delete("/delete-account/:id", authMiddleware, async (req, res) => {
  const { password } = req.body;
  const userId = Number(req.params.id);

  try {
    const user = await User.findOne({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Неверный пароль." });
    }

    await user.destroy();

    res.status(200).json({ message: "Аккаунт успешно удален." });
  } catch (error) {
    handleError(res, error, "Ошибка при удалении аккаунта.");
  }
});

app.get(
  "/admin/:id",
  authMiddleware,
  authorizeRoleMiddleware("admin"),
  async (req, res) => {
    const userId = Number(req.params.id);
    try {
      const user = await User.findOne({ where: { id: userId } });

      if (!user) {
        return res.status(404).json({ error: "Пользователь не найден." });
      }

      res.status(200).json({ message: "Добро пожаловать, администратор!" });
    } catch (error) {
      handleError(res, error, "Ошибка при удалении аккаунта.");
    }
  }
);

app.put("/change-email/:id", authMiddleware, async (req, res) => {
  const { currentPassword, newEmail } = req.body;
  const userId = Number(req.params.id);

  try {
    const user = await User.findOne({ where: { id: userId } });

    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password
    );
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Неверный пароль." });
    }

    const existingUser = await userExists(newEmail);
    if (existingUser) {
      return res.status(400).json({ error: "Email уже используется." });
    }
    user.email = newEmail;
    await user.save();

    res.status(200).json({ message: "Email успешно обновлен." });
  } catch (error) {
    handleError(res, error, "Ошибка при изменении email.");
  }
});

app.listen(PORT, async () => {
  try {
    await sequelize.authenticate();
    console.log(`server connect to port http://localhost:${PORT}`);
  } catch (error) {
    console.error("Error to connect", error);
  }
});
