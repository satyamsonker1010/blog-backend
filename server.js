import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt, { hash } from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import serviceAccountKey from "./blog-55101-firebase-adminsdk-c7x88-ebecc9670c.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";
import fs from "fs";
import aws from "aws-sdk";

//Schema
import User from "./Schema/User.js";
const server = express();
server.use(express.json());

// const serviceAccountKey = JSON.parse(
//   fs.readFileSync(
//     "./blog-55101-firebase-adminsdk-c7x88-ebecc9670c.json",
//     "utf8"
//   )
// );

let port = 3000;
admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});
server.use(cors());
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

// Setting up s3  bucket
const s3 = new aws.S3({
  region: "ap-south-1",
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const generateUploadURL = async () => {
  const date = new Date();
  const imageName = `${nanoid()}-${date.getTime()}.jpg`;
  return await s3.getSignedUrl("putObject", {
    Bucket: "blogging-website-hoogaaa",
    Key: imageName,
    Expires: 1000,
    ContentType: "image/jpeg",
  });
};

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

const formatDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

async function generateUsername(email) {
  let userName = email.split("@")[0];

  let usernameIsUnique = await User.exists({
    "personal_info.username": userName,
  }).then((result) => result);
  usernameIsUnique ? (userName += nanoid().substring(0, 7).toLowerCase()) : "";
  return userName;
}

server.get("/get-upload-url", (req, res) => {
  generateUploadURL()
    .then((url) => {
      return res.status(200).json({ uploadURL: url });
    })
    .catch((error) => {
      return res.status(500).json({ error: error.message });
    });
});

server.post("/signup", (req, res) => {
  let { fullname, email, password } = req.body;
  //validating the data from frontend
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Fullname must br at least 3 letters long" });
  }
  if (!email.length) {
    return res.status(403).json({ error: "Enter email" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email adddress is not correct." });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long with a number, 1 lowercase and 1 uppercase letters.",
    });
  }
  bcrypt.hash(password, 10, async (err, hashPassword) => {
    let username = await generateUsername(email);
    let user = new User({
      personal_info: { fullname, email, password: hashPassword, username },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDatatoSend(u));
      })
      .catch((err) => {
        if (err.code === 11000) {
          return res.status(403).json({ error: "Email already exists." });
        }
        return res.status(500).json({ error: err.message });
      });
  });
});

server.post("/signin", (req, res) => {
  let { email, password } = req.body;
  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res
              .status(403)
              .json({ error: "Error occured while login please try again" });
          }
          if (!result) {
            return res.status(401).json({ error: "Incorrect password" });
          } else {
            return res.status(200).json(formatDatatoSend(user));
          }
        });
      } else {
        return res.status(403).json({
          error:
            "Account was created using google. Try logging in with google.",
        });
      }
    })
    .catch((error) => {
      return res.status(500).json({ error: error.message });
    });
});

server.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;
  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;
      picture = picture.replace("s96-c", "s384-c");
      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username  personal_info.profile_img google_auth"
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });

      if (user) {
        if (!user.google_auth) {
          return res.status(403).json({
            error:
              "This email was signed up with google. Please log in with password to access the account.",
          });
        }
      } else {
        let username = await generateUsername(email);
        user = new User({
          personal_info: { fullname: name, email, username },
          google_auth: true,
        });

        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json({ error: err.message });
          });
      }
      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({
        error:
          "Failed to authenticate you with google. Try with some other google account.",
      });
    });
});

server.listen(port, () => {
  console.log("listening on port ->", port);
});
