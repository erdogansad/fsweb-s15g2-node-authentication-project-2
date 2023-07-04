const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const { goreBul } = require("../users/users-model");

const sinirli = (req, res, next) => {
  if (!req.headers.authorization) {
    return next({ status: 401, message: "Token gereklidir" });
  } else {
    const token = req.headers.authorization;
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
      if (err) {
        next({ status: 401, message: "Token gecersizdir" });
      } else {
        req.decodedToken = decodedToken;
        next();
      }
    });
  }
};

const sadece = (role_name) => (req, res, next) => {
  if (role_name === req.decodedToken.role_name) {
    next();
  } else {
    next({ status: 403, message: "Bu, senin için değil" });
  }
};

const usernameVarmi = async (req, res, next) => {
  try {
    const [user] = await goreBul({ username: req.body.username });
    if (!user) {
      next({ status: 401, message: "Geçersiz kriter" });
    } else {
      req.user = user;
      next();
    }
  } catch (e) {
    next(e);
  }
};

const rolAdiGecerlimi = (req, res, next) => {
  if (req.body.role_name) {
    req.body.role_name = req.body.role_name.trim();
    if (req.body.role_name === "") {
      req.body.role_name = "student";
      next();
    } else {
      if (req.body.role_name === "admin") {
        next({ status: 422, message: "Rol adı admin olamaz" });
      } else if (req.body.role_name.length > 32) {
        next({ status: 422, message: "rol adı 32 karakterden fazla olamaz" });
      } else {
        next();
      }
    }
  } else {
    req.body.role_name = "student";
    next();
  }
};

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
};
