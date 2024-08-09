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

  const user = await User.findOne({ username });

  console.log(user);

  let hashedPassword = null;

  if (req.body.password) {
    //zod validation of password
    const passResponse = passSchema.safeParse(req.body.password);

    if (!passResponse.success)
      return res
        .status(404)
        .json({ message: "Password should be of 6 or more characters" });

    //checking if last password is same
    if (await user.validatePassword(req.body.password))
      return res
        .status(404)
        .json({ message: "Password should not be same as last password" });

    //creating hashed password
    hashedPassword = await user.createHash(req.body.password);
    req.body.password = hashedPassword;
  }

  await user.updateOne(req.body);

  res.json({ message: "successfully updated" });
});

router.get("/bulk", authMiddleware, async (req, res) => {
  const { filter } = req.query;

  const searchName = filter;
  const nameParts = searchName.split(" ");

  let query = {};

  if (nameParts.length == 2) {
    //if I am getting both first and last name
    const [firstName, lastName] = nameParts;

    query = {
      firstName: new RegExp(firstName, "i"),
      lastName: new RegExp(lastName, "i"),
    };
  } else if (nameParts.length == 1) {
    //if I am getting either first or last name
    const name = nameParts[0];

    query = {
      $or: [
        { firstName: new RegExp(name, "i") },
        { lastName: new RegExp(name, "i") },
      ],
    };
  }

  const searchResult = await User.find(query);

  res.status(202).json({ users: searchResult });
});

module.exports = router;
