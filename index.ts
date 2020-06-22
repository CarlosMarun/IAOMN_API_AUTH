import express, { Request, Response, response } from "express";
import cors from "cors";
import ENV from "./environments/env.production";
//JSON WEB TOKEN IMPORT
import jwt from "jsonwebtoken";
//Import MIDDLEWARE
import AuthToken from "./middlewares/token.middleware";
// Helper import
import MongoDBHelper from "./helpers/mongodb.helper";
//IMPORT BCRYPTJS
import bcrypt from "bcryptjs";
import { ObjectId, ObjectID } from "mongodb";

const app = express();
const port = ENV.API.PORT;
const token = AuthToken();
const mongoDB = MongoDBHelper.getInstance(ENV.MONGODB);

//Middlewares for API
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
//Middleware for CORS
app.use(cors({ origin: true, credentials: true }));

app.get("/api/auth/test", (req: Request, res: Response) => {
  res.status(200).json({
    ok: true,
    msg: "API de AUTH funcionando correctamente!",
  });
});

app.post("/api/auth/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = await mongoDB.db.collection("users").findOne({ email: email });

  if (user) {
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(403).json({
        ok: false,
        msg:
          "Lo sentimos el usuario y/o contraseña no validos. Favor de verificar!",
      });
    }
    const userValid = {
      uid: user._id,
      email: user.email,
      fullName: user.fullName,
      urlPhoto: user.urlPhoto,
      rol: user.rol,
    };

    jwt.sign(
      userValid,
      "secretkeyword",
      { expiresIn: "600s" },
      (err: any, token) => {
        if (err) {
          return res.status(500).json({
            ok: false,
            msg: "Ocurrio un error :s",
            err,
          });
        }
        res.status(200).json({
          ok: true,
          msg: "Usuario logeado",
          token,
          userValid,
        });
      }
    );
  } else {
    res.status(404).json({
      ok: false,
      msg:
        "Lo sentimos el usuario y/o contraseña no validos. Favor de verificar!",
    });
  }
});

app.get(
  "/api/auth/getCustomers",
  token.verify,
  (req: Request, res: Response) => {
    const { authUser } = req.body;
    const mockCustomer = [
      {
        clave: "CAMR",
        nombre: "Carlos CO.",
      },
      {
        clave: "CAMR69",
        nombre: "Carlos trademark.",
      },
    ];
    res.status(200).json({
      ok: true,
      msg: "Permiso de acceso concedido",
      mockCustomer,
      user: authUser,
    });
  }
);

app.get(
  "/api/auth/getUsers",
  token.verify,
  async (req: Request, res: Response) => {
    const users = await mongoDB.db.collection("users").find({}).toArray();

    if (users.length !== 0) {
      res.status(200).json({
        ok: true,
        users: [users],
      });
    } else {
      res.status(404).json({
        ok: false,
        msg: "Nada por aqui!",
      });
    }
  }
);

app.post("/api/auth/createUser", async (req: Request, res: Response) => {
  const { email, password, fullName, urlPhoto, rol } = req.body;
  const user = {
    email,
    password: bcrypt.hashSync(password, 10),
    fullName,
    urlPhoto,
    rol,
  };
  const validateUser = await mongoDB.db.collection("users").findOne({ email });

  if (!validateUser) {
    const insert = await mongoDB.db.collection("users").insertOne(user);
    res.status(200).json({
      ok: true,
      msg: "Insertado correctamente",
      uid: insert.insertedId,
    });
  } else {
    res.status(403).json({
      ok: false,
      msg: "El usuario ya existe",
    });
  }
});

app.post(
  "/api/auth/deleteUser",
  token.verify,
  async (req: Request, res: Response) => {
    const { id } = req.body;

    const validateUser = await mongoDB.db
      .collection("users")
      .findOne({ _id: new ObjectId(id) });
    if (!validateUser) {
      res.status(403).json({
        ok: false,
        msg: "El usuario no existe",
      });
    } else {
      const deleted = await mongoDB.db
        .collection("users")
        .deleteOne({ _id: new ObjectID(id) });
      res.status(200).json({
        ok: true,
        msg: "Eliminado correctamente",
        deletedCount: deleted.deletedCount,
      });
    }
  }
);

app.listen(port, async () => {
  console.log(`Servidor de API funcionando en puerto ${port}`);
  // Connect to MongoDB
  await mongoDB.connect();
});

// Handle Errors
process.on("unhandledRejection", async (err: any) => {
  //Close MongoDB cnn
  mongoDB.close();
  process.exit();
});
