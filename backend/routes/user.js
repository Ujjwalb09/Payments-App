const express = require("express");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");
const { User } = require("../db");
const router = express.Router();
const authMiddleware = require("../middlewares/middleware");
const zod = require("zod");
const emailSchema = zod.string().email();
const passSchema = zod.string().min(6);

//user Signup
router.post("/signup", async (req, res) => {
  //zod validations
  const usernameResponse = emailSchema.safeParse(req.body.username);
  const passResponse = passSchema.safeParse(req.body.password);

  if (!usernameResponse.success)
    return res.json({
      message: "Invalid Email",
    });
  else if (!passResponse.success)
    return res.json({
      message: "Password should be of more than 6 characters",
    });

  const newUser = new User({
    username: req.body.username,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  });

  const hashedPassword = await newUser.createHash(req.body.password);
  newUser.password = hashedPassword;

  const token = jwt.sign({ username: req.body.username }, JWT_SECRET);

  try {
    await newUser.save();
  } catch (error) {
    return res.status(411).json({
      message: "Email already in use / Incorrect inputs",
    });
  }

  res.json({
    message: "User created successfully",
    token,
  });
});

router.post("/signin", authMiddleware, async (req, res) => {
  const user = await User.findOne({ username: req.body.username });

  // checking if user exists in DB
  if (!user)
    return res.status(400).json({
      message: "User not found",
    });

  //checking if password is correct
  if (!(await user.validatePassword(req.body.password)))
    return res.status(400).json({
      message: "Incorrect Password",
    });

  const token = jwt.sign({ username: user.username }, JWT_SECRET);

  res.status(200).json({ message: "User Successfully Logged In", token });
});

module.exports = router;
