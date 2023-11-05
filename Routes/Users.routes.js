const express = require('express');
const UserRouter = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const User = require('../Models/User.model');
const multer = require('multer');
const serviceAccount = require('../auction-app-dcd79-firebase-adminsdk-cf6d6-93c69eac03.json');
const nodemailer = require("nodemailer")
const authenticate = require('../Middleware/authMiddlware');
const crypto = require("crypto");
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
        user: "altlakshi@gmail.com",
        pass: "jzle plal lxvf pilt",
    },
});

const bucket = admin.storage().bucket('gs://auction-app-dcd79.appspot.com');
// Register a new user
UserRouter.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Check if a user with the same email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email.' });
        }

        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
        });

        await newUser.save();

        // Optionally, generate a JWT token and send it as a response
        const token = jwt.sign({ userId: newUser._id }, 'your-secret-key', { expiresIn: '7d' });

        res.status(201).json({ message: 'User registered successfully', token, user: newUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while registering the user.' });
    }
});

// Log in a user
UserRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate a JWT token for authentication
        const token = jwt.sign({ userId: user._id }, 'your-secret-key', { expiresIn: '7d' });

        res.status(200).json({ message: 'User logged in successfully', token, user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while logging in.' });
    }
});

UserRouter.get('/users', async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json({ users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while fetching users.' });
    }
});
const upload = multer({
    storage: multer.memoryStorage(),
});
UserRouter.post('/upload', upload.single('image'), async (req, res) => {
    try {
        const file = req.file;

        if (!file) {
            return res.status(400).send('No file uploaded.');
        }

        const fileName = `${Date.now()}-${file.originalname}`;
        const fileUpload = bucket.file(fileName);

        // Create a writable stream to upload the image
        const stream = fileUpload.createWriteStream({
            metadata: {
                contentType: file.mimetype,
            },
        });

        stream.on('error', (error) => {
            return res.status(500).send('Error uploading file: ' + error.message);
        });

        stream.on('finish', async () => {
            // Make the image publicly accessible
            await fileUpload.makePublic();

            const imageUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;
            res.json({ imageUrl });
        });

        // Pipe the image data into the writable stream
        stream.end(file.buffer);
    } catch (error) {
        res.status(500).send('Something went wrong: ' + error.message);
    }
});
UserRouter.patch("/update/user/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { name, profileImage } = req.body;
        const user = await User.findByIdAndUpdate(id, { name, profileImage }, { new: true });
        res.status(200).json({ user });
    }
    catch (error) {
        res.status(500).send('Something went wrong: ' + error.message);
    }
})

UserRouter.get("/user/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id);
        res.status(200).json({ user });
    }
    catch (error) {
        res.status(500).send('Something went wrong: ' + error.message);
    }
});
UserRouter.put('/update_password/:userId', async (req, res) => {
    const userId = req.params.userId;
    const { oldPassword, newPassword } = req.body;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify the old password
        if (await bcrypt.compare(oldPassword, user.password)) {
            // Hash and update the new password
            const newPasswordHash = await bcrypt.hash(newPassword, 10);
            user.password = newPasswordHash;
            await user.save();
            return res.status(200).json({ message: 'Password updated successfully' });
        } else {
            return res.status(401).json({ message: 'Incorrect old password' });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error' });
    }
});


UserRouter.get('/getUserDetails', authenticate, async (req, res) => {
    const userId = req.user.userId; // Assuming you have the user ID in req.user.userId after authentication

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Send user details as a JSON response
        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});


UserRouter.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetTokenExpiration = Date.now() + 3600000;

        user.resetToken = resetToken;
        user.resetTokenExpiration = resetTokenExpiration;
        await user.save();
        let emialHtml = `<!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta http-equiv="X-UA-Compatible" content="IE=edge">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Password Reset</title>
        </head>
        <body style="font-family: Arial, sans-serif;">
        
          <div style="padding: 20px;">
            <h2>Password Reset</h2>
            <p>Hello ${user.name},</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="http://localhost:5173/reset-password?token=${resetToken}" style="text-decoration: none; background-color: #3498db; color: white; padding: 10px 20px; border-radius: 5px;">Reset Your Password</a></p>
            <p>If you didn't request a password reset, you can ignore this email.</p>
            <p>Best regards,<br>Chaitfy</p>
          </div>
        </body>
        </html>
        `
        const mailOptions2 = {
            from: "altlakshi@gmail.com",
            to: email,
            subject: "Reset Password Link <Read Required>",
            html: emialHtml,
        };
        transporter.sendMail(mailOptions2, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
                return res.status(500).json({ message: "Error sending email." });
            }
            console.log("Email sent:", info.response);
            res.json({ message: 'Reset link sent successfully.' });
        });

    } catch (error) {
        console.error('Error sending reset link:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

UserRouter.post('/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetToken,
            resetTokenExpiration: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token.' });
        }

        // Update the user's password
        const hash = await bcrypt.hash(newPassword, 10);
        user.password = hash;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        res.json({ message: 'Password reset successful.' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

module.exports = UserRouter;
