const mongoose = require("mongoose");

const projectSchema = new mongoose.Schema({
  regNo: { type: String, required: true },
  title: { type: String, required: true },
  type: { type: String, default: "Software" },
  tools: String,
  desc: { type: String, required: true },
  status: { type: String, default: "Pending" },
  image: String,
  report: { type: String, required: true },
  likes: { type: Number, default: 0 },
  likedUsers: { type: [String], default: [] },
  rating: { type: Number, default: 0 },

});

const Project = mongoose.model("Project", projectSchema);

module.exports = Project;
