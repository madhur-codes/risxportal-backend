const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const authenticate = require("../middleware/auth");
const prisma = require("../lib/prisma");

const router = express.Router();

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function createToken(user) {
    if (!process.env.JWT_SECRET) {
        throw new Error(
            "JWT_SECRET is missing from environment variables."
        );
    }

    return jwt.sign(
        {
            userId: user.id,
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

/*
|--------------------------------------------------------------------------
| REGISTER
|--------------------------------------------------------------------------
| Registration now creates the account immediately.
| No OTP / email verification is required.
|--------------------------------------------------------------------------
*/

router.post("/register", async (req, res) => {
    try {
        const {
            name,
            email,
            password
        } = req.body || {};

        // Validate required fields
        if (!name || !email || !password) {
            return res.status(400).json({
                message:
                    "Name, email and password are required."
            });
        }

        const cleanName = String(name).trim();
        const normalizedEmail = normalizeEmail(email);
        const cleanPassword = String(password);

        // Validate name
        if (cleanName.length < 2) {
            return res.status(400).json({
                message: "Please enter a valid name."
            });
        }

        // Validate email
        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({
                message:
                    "Please enter a valid email address."
            });
        }

        // Validate password
        if (cleanPassword.length < 6) {
            return res.status(400).json({
                message:
                    "Password must be at least 6 characters."
            });
        }

        console.log(
            "📝 Registration request:",
            normalizedEmail
        );

        // Check if user already exists
        const existingUser =
            await prisma.user.findUnique({
                where: {
                    email: normalizedEmail
                }
            });

        if (existingUser) {
            return res.status(409).json({
                message:
                    "An account with this email already exists. Please login."
            });
        }

        // Hash password
        const hashedPassword =
            await bcrypt.hash(
                cleanPassword,
                12
            );

        // Create user immediately
        const user =
            await prisma.user.create({
                data: {
                    name: cleanName,
                    email: normalizedEmail,
                    password: hashedPassword
                },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true,
                    createdAt: true
                }
            });

        // Create JWT
        const token = createToken(user);

        console.log(
            "✅ User registered:",
            user.email
        );

        return res.status(201).json({
            message:
                "Account created successfully.",
            token,
            user
        });

    } catch (error) {
        console.error(
            "❌ Registration error:",
            error
        );

        return res.status(500).json({
            message:
                "Something went wrong while creating the account."
        });
    }
});

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

router.post("/login", async (req, res) => {
    try {
        const {
            email,
            password
        } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({
                message:
                    "Email and password are required."
            });
        }

        const normalizedEmail =
            normalizeEmail(email);

        const user =
            await prisma.user.findUnique({
                where: {
                    email: normalizedEmail
                }
            });

        if (!user) {
            return res.status(401).json({
                message:
                    "Invalid email or password."
            });
        }

        const passwordCorrect =
            await bcrypt.compare(
                String(password),
                user.password
            );

        if (!passwordCorrect) {
            return res.status(401).json({
                message:
                    "Invalid email or password."
            });
        }

        const token = createToken(user);

        console.log(
            "✅ User logged in:",
            user.email
        );

        return res.json({
            message:
                "Login successful.",
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error(
            "❌ Login error:",
            error
        );

        return res.status(500).json({
            message:
                "Something went wrong while logging in."
        });
    }
});

/*
|--------------------------------------------------------------------------
| GET CURRENT USER
|--------------------------------------------------------------------------
*/

router.get(
    "/me",
    authenticate,
    async (req, res) => {
        try {
            const user =
                await prisma.user.findUnique({
                    where: {
                        id: req.user.userId
                    },
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        role: true,
                        createdAt: true
                    }
                });

            if (!user) {
                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            return res.json({
                user
            });

        } catch (error) {
            console.error(
                "❌ Get user error:",
                error
            );

            return res.status(500).json({
                message:
                    "Failed to retrieve user."
            });
        }
    }
);

module.exports = router;