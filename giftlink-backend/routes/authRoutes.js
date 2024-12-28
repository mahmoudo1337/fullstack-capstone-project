const express = require("express");
const app = express();
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const connectToDatabase = require("../models/db");
const router = express.Router();
const dotenv = require("dotenv");
const pino = require("pino");

const logger = pino();
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post("/register", async (req, res) => {
  try {
    // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
    const db = await connectToDatabase();
    // Task 2: Access MongoDB collection
    const collection = db.collection("users");
    //Task 3: Check for existing email
    const existingEmail = await collection.findOne({ email: req.body.email });
    const salt = await bcryptjs.genSalt(10);
    const hash = await bcryptjs.hash(req.body.password, salt);
    const email = req.body.email;
    if (existingEmail) {
      return res.status(400).send("Email already exists");
    }
    //Task 4: Save user details in database
    const newUser = await collection.insertOne({
      email: email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    });
    //Task 5: Create JWT authentication with user._id as payload
    const payload = {
      user: {
        id: newUser.insertedId,
      },
    };
    const authtoken = jwt.sign(payload, JWT_SECRET);

    logger.info("User registered successfully");
    res.json({ authtoken, email });
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

router.post("/login", async (req, res) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection("users");
    const existingUser = await collection.findOne({ email: req.body.email });
    if (existingUser) {
      let result = await bcryptjs.compare(
        req.body.password,
        existingUser.password
      );
      if (!result) {
        logger.error("Passwords do not match");
        return res.status(404).json({ error: "Wrong pasword" });
      }
      let payload = {
        user: {
          id: existingUser._id.toString(),
        },
      };
      const userName = existingUser.firstName;
      const userEmail = existingUser.email;
      const authtoken = jwt.sign(payload, JWT_SECRET);
      logger.info("User logged in successfully");
      return res.status(200).json({ authtoken, userName, userEmail });
    } else {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

module.exports = router;
