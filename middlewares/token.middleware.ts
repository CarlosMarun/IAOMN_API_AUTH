import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export default () => {
  return {
    verify: (req: Request, res: Response, next: NextFunction) => {
      // Get Auth Header Value
      const bearerHeader = req.headers["authorization"];
      //
      if (typeof bearerHeader !== "undefined") {
        // Split
        const bearer = bearerHeader.split(" ");
        // Get Token from Array
        const bearerToken = bearer[1];
        // Verify Token
        jwt.verify(
          bearerToken,
          "secretkeyword",
          (err: any, tokenDecoded: any) => {
            if (err) {
              // Forbidden
              return res.status(403).json({
                ok: false,
                msg:
                  "Lo sentimos, usted no tiene acceso. Favor de verificar su token",
              });
            }
            req.body.authUser = tokenDecoded;
            next();
          }
        );
      } else {
        //Unauthorized
        return res.status(401).json({
          ok: false,
          msg:
            "Lo sentimos el acceso esta restringido. requiere iniciar sesión para acceder",
        });
      }
    },
  };
};
