const express = require("express");
const { User } = require("../db");
const router = express.Router();

//user Signup
router.post("/signup", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  });
  const hashedPassword = await newUser.createHash(req.body.password);
  newUser.password = hashedPassword;

  await newUser.save();

  return res.json("done");
});

module.exports = router;
