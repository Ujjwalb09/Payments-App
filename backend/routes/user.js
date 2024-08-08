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
      message: "Password should be of 6 or more characters",
    });

  const newUser = new User({
    username: req.body.username,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  });

  const hashedPassword = await newUser.createHash(req.body.password);
  newUser.password = hashedPassword;

  const token =
    "Bearer " + jwt.sign({ username: req.body.username }, JWT_SECRET);

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

router.post("/signin", async (req, res) => {
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

  const token = "Bearer " + jwt.sign({ username: user.username }, JWT_SECRET);

  res.status(200).json({ message: "User Successfully Logged In", token });
});

router.put("/update", authMiddleware, async (req, res) => {
  const username = req.username;

  //zod validation of password
  const passResponse = passSchema.safeParse(req.body.password);

  if (!passResponse.success)
    return res
      .status(404)
      .json({ message: "Password should be of 6 or more characters" });

  const user = await User.findOne({ username });

  //checking if last password is same
  if (await user.validatePassword(req.body.password))
    return res
      .status(404)
      .json({ message: "Password should not be same as last password" });

  const updated = {
    password: req.body.password,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  };

  //creating hashed password
  const hashedPassword = await user.createHash(updated.password);

  await user.updateOne({
    $set: {
      password: hashedPassword,
      firstName: updated.firstName,
      lastName: updated.lastName,
    },
  });

  res.json({ message: "successfully updated" });
});

router.get("/bulk", authMiddleware, async (req, res) => {
  const { filter } = req.query;

  const searchName = filter;

  const users = await User.find();

  const searchResult = users
    .filter((user) => user.firstName.toLowerCase() === searchName)
    .map((user) => ({
      firstName: user.firstName,
      lastName: user.lastName,
      id: user._id,
    }));

  res.status(202).json({ users: searchResult });
});

module.exports = router;
