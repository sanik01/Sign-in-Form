const crypto = require("crypto");
const express = require("express");
const mongoose = require("mongoose"); 
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost:27017/node-auth", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  mobileNumber: { type: String, required: true },
  gender: { type: String, required: true },
  password: { type: String, required: true },
  isPremium: { type: Boolean, default: false },
  premiumPackage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "PremiumPackage",
  },
});

userSchema.pre("save", async function (next) {
  const user = this;
  if (user.isModified("password")) {
    user.password = await bcrypt.hash(user.password, 10);
  }
  next();
});

const User = mongoose.model("User", userSchema);

// PremiumPackage schema and model
const premiumPackageSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  validity: { type: Number, required: true },
  mostPopular: { type: Boolean, default: false },
});

const PremiumPackage = mongoose.model("PremiumPackage", premiumPackageSchema);

// Middleware
app.use(express.json());
// Endpoint to create a premium package
app.post("/api/create-package", async (req, res) => {
  try {
    const { amount, validity, mostPopular } = req.body;

    const newPackage = new PremiumPackage({ amount, validity, mostPopular });
    const savedPackage = await newPackage.save();

    res.status(201).json({
      message: "Premium package created successfully",
      packageId: savedPackage._id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Sign-up endpoint
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, mobileNumber, gender, password, confirmPassword } =
      req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const newUser = new User({ name, email, mobileNumber, gender, password });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "365d",
    });

    res.status(201).json({ message: "User created successfully", token });
  } catch (err) {
 
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "365d",
    });

    res.json({ message: "Sign in successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email not found" });
    }

    // Generate a random reset token with expiration
    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetTokenExpiry;
    await user.save();

    // Send the reset password email (implementation omitted for brevity)
    // Use a secure email service to send a link containing the reset token

    res
      .status(200)
      .json({ message: "Password reset instructions sent to your email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});


const verifyJWT = (req, res, next) => {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

app.get("/api/premium-packages", async (req, res) => {
  try {
    const packages = await PremiumPackage.find();
    res.json(packages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/purchase-premium", verifyJWT, async (req, res) => {
  try {
    const userId = req.userId;
    console.log(userId, "inside purchase");

    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ message: "Invalid user" });
    }

    // Extract packageId from request body
    const { packageId } = req.body; 

    const premiumPackage = await PremiumPackage.findById(packageId);
    if (!premiumPackage) {
      return res.status(400).json({ message: "Invalid package" });
    }

    user.isPremium = true;
    user.premiumPackage = premiumPackage._id;

    // Save the updated user with the package relationship
    await user.save();

  
    res.json({
      message: "Premium package purchased successfully",
      validity: premiumPackage.validity,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
