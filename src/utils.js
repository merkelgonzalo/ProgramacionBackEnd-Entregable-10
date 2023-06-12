import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcrypt';
import Jwt from "jsonwebtoken";

export const createHash = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10));
export const validatePassword = (password, user) => bcrypt.compareSync(password, user.password);

const PRIVATE_KEY = "my-secret-key";

export const generateToken = (user) => {
    const token = Jwt.sign(
      {
        user,
      },
      PRIVATE_KEY,
      { expiresIn: "1d" }
    );
    return token;
  };
  export const authToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "error" });
    console.log(authHeader);
    const token = authHeader.split(" ")[1];
    if (token === null)
      return res.status(401).json({ message: "error en el token" });
    Jwt.verify(token, PRIVATE_KEY, (err, credentials) => {
      if (err) return res.status(401).json({ message: "No autorizado" });
      req.user = credentials.user;
      next();
    });
  };

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


export default __dirname;