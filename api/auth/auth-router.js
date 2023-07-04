const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const { ekle } = require("../users/users-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  try {
    const { username, password, role_name } = req.body;
    const hash = await bcrypt.hash(password, 8);
    const newUser = { username, password: hash, role_name };
    const user = await ekle(newUser);
    res.status(201).json(user);
  } catch (e) {
    next(e);
  }
});

router.post("/login", usernameVarmi, (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (bcrypt.compareSync(password, req.user.password)) {
      const token = jwt.sign({ subject: req.user.user_id, username: req.user.username, role_name: req.user.role_name }, JWT_SECRET, { expiresIn: "1d" });
      res.json({
        message: `${username} geri geldi!`,
        token,
      });
    } else {
      next({ status: 401, message: "Geçersiz kriter" });
    }
  } catch (e) {
    next(e);
  }
});

module.exports = router;
