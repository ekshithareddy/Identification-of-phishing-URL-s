const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  regNo: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  dept: { type: String, required: true },
  batch: { type: String },
  email: { type: String, required: true },
  role: { type: String, enum: ["student", "staff"], required: true },
});

module.exports = mongoose.model("User", userSchema);
