const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const authenticate = require("../middleware/auth");
const prisma = require("../lib/prisma");

const router = express.Router();

// ==========================================================
// EMAIL TRANSPORTER
// ==========================================================

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// ==========================================================
// HELPERS
// ==========================================================

function generateOTP() {
    return crypto.randomInt(100000, 1000000).toString();
}

function hashOTP(otp) {
    return crypto
        .createHash("sha256")
        .update(String(otp))
        .digest("hex");
}

function createToken(user) {
    if (!process.env.JWT_SECRET) {
        throw new Error("JWT_SECRET is missing from .env");
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

// ==========================================================
// REGISTER
// ==========================================================

router.post("/register", async (req, res) => {
    try {
        const {
            name,
            email,
            password
        } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message:
                    "Name, email and password are required."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message:
                    "Password must be at least 6 characters."
            });
        }

        const normalizedEmail =
            email.toLowerCase().trim();

        const cleanName =
            name.trim();

        // --------------------------------------------------
        // CHECK EXISTING USER
        // --------------------------------------------------

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

        // --------------------------------------------------
        // CHECK EXISTING VERIFICATION
        // --------------------------------------------------

        await prisma.emailVerification.deleteMany({
            where: {
                email: normalizedEmail
            }
        });

        // --------------------------------------------------
        // HASH PASSWORD
        // --------------------------------------------------

        const hashedPassword =
            await bcrypt.hash(password, 12);

        // --------------------------------------------------
        // GENERATE OTP
        // --------------------------------------------------

        const otp =
            generateOTP();

        const otpHash =
            hashOTP(otp);

        const expiresAt =
            new Date(
                Date.now() + 10 * 60 * 1000
            );

        // --------------------------------------------------
        // CREATE EMAIL VERIFICATION
        // --------------------------------------------------

        await prisma.emailVerification.create({
            data: {
                name: cleanName,
                email: normalizedEmail,
                password: hashedPassword,
                otpHash,
                expiresAt
            }
        });

        // --------------------------------------------------
        // SEND OTP
        // --------------------------------------------------

        try {
            await sendOTPEmail(
                normalizedEmail,
                cleanName,
                otp
            );
        } catch (emailError) {
            console.error(
                "OTP email error:",
                emailError
            );

            await prisma.emailVerification.deleteMany({
                where: {
                    email: normalizedEmail
                }
            });

            return res.status(500).json({
                message:
                    "Unable to send verification email. Please try again."
            });
        }

        return res.status(201).json({
            message:
                "Account verification OTP sent to your email.",
            requiresVerification: true,
            email: normalizedEmail
        });

    } catch (error) {
        console.error(
            "Registration error:",
            error
        );

        return res.status(500).json({
            message:
                "Something went wrong while creating the account."
        });
    }
});

// ==========================================================
// VERIFY OTP
// ==========================================================

router.post("/verify-otp", async (req, res) => {
    try {
        const {
            email,
            otp
        } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                message:
                    "Email and OTP are required."
            });
        }

        const normalizedEmail =
            email.toLowerCase().trim();

        // --------------------------------------------------
        // FIND VERIFICATION
        // --------------------------------------------------

        const verification =
            await prisma.emailVerification.findUnique({
                where: {
                    email: normalizedEmail
                }
            });

        if (!verification) {
            return res.status(404).json({
                message:
                    "No pending verification found. Please register again."
            });
        }

        // --------------------------------------------------
        // CHECK EXPIRY
        // --------------------------------------------------

        if (
            new Date() >
            new Date(verification.expiresAt)
        ) {
            return res.status(400).json({
                message:
                    "OTP has expired. Please request a new OTP."
            });
        }

        // --------------------------------------------------
        // CHECK ATTEMPTS
        // --------------------------------------------------

        if (verification.attempts >= 5) {
            return res.status(429).json({
                message:
                    "Too many incorrect attempts. Please request a new OTP."
            });
        }

        // --------------------------------------------------
        // CHECK OTP
        // --------------------------------------------------

        const submittedHash =
            hashOTP(String(otp).trim());

        if (
            submittedHash !==
            verification.otpHash
        ) {
            await prisma.emailVerification.update({
                where: {
                    id: verification.id
                },
                data: {
                    attempts: {
                        increment: 1
                    }
                }
            });

            return res.status(400).json({
                message:
                    "Invalid OTP."
            });
        }

        // --------------------------------------------------
        // CHECK IF USER WAS CREATED SOMEHOW
        // --------------------------------------------------

        const existingUser =
            await prisma.user.findUnique({
                where: {
                    email: normalizedEmail
                }
            });

        if (existingUser) {
            await prisma.emailVerification.delete({
                where: {
                    id: verification.id
                }
            });

            return res.status(409).json({
                message:
                    "An account with this email already exists. Please login."
            });
        }

        // --------------------------------------------------
        // CREATE VERIFIED USER
        // --------------------------------------------------

        const user =
            await prisma.user.create({
                data: {
                    name: verification.name,
                    email: verification.email,
                    password: verification.password
                },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true,
                    createdAt: true
                }
            });

        // --------------------------------------------------
        // DELETE VERIFICATION RECORD
        // --------------------------------------------------

        await prisma.emailVerification.delete({
            where: {
                id: verification.id
            }
        });

        // --------------------------------------------------
        // CREATE JWT
        // --------------------------------------------------

        const token =
            createToken(user);

        return res.json({
            message:
                "Email verified successfully.",
            token,
            user
        });

    } catch (error) {
        console.error(
            "OTP verification error:",
            error
        );

        return res.status(500).json({
            message:
                "Something went wrong while verifying your email."
        });
    }
});

// ==========================================================
// RESEND OTP
// ==========================================================

router.post("/resend-otp", async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message:
                    "Email is required."
            });
        }

        const normalizedEmail =
            email.toLowerCase().trim();

        const verification =
            await prisma.emailVerification.findUnique({
                where: {
                    email: normalizedEmail
                }
            });

        if (!verification) {
            return res.status(404).json({
                message:
                    "No pending verification found. Please register again."
            });
        }

        const otp =
            generateOTP();

        const otpHash =
            hashOTP(otp);

        const expiresAt =
            new Date(
                Date.now() + 10 * 60 * 1000
            );

        await prisma.emailVerification.update({
            where: {
                id: verification.id
            },
            data: {
                otpHash,
                expiresAt,
                attempts: 0
            }
        });

        await sendOTPEmail(
            normalizedEmail,
            verification.name,
            otp
        );

        return res.json({
            message:
                "A new OTP has been sent to your email."
        });

    } catch (error) {
        console.error(
            "Resend OTP error:",
            error
        );

        return res.status(500).json({
            message:
                "Unable to resend OTP."
        });
    }
});

// ==========================================================
// LOGIN
// ==========================================================

router.post("/login", async (req, res) => {
    try {
        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message:
                    "Email and password are required."
            });
        }

        const normalizedEmail =
            email.toLowerCase().trim();

        // --------------------------------------------------
        // FIND USER
        // --------------------------------------------------

        const user =
            await prisma.user.findUnique({
                where: {
                    email: normalizedEmail
                }
            });

        // --------------------------------------------------
        // USER DOES NOT EXIST
        // --------------------------------------------------

        if (!user) {
            return res.status(401).json({
                message:
                    "Invalid email or password."
            });
        }

        // --------------------------------------------------
        // PASSWORD CHECK
        // --------------------------------------------------

        const passwordCorrect =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordCorrect) {
            return res.status(401).json({
                message:
                    "Invalid email or password."
            });
        }

        // --------------------------------------------------
        // CREATE TOKEN
        // --------------------------------------------------

        const token =
            createToken(user);

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
            "Login error:",
            error
        );

        return res.status(500).json({
            message:
                "Something went wrong while logging in."
        });
    }
});

// ==========================================================
// GET CURRENT USER
// ==========================================================

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
                "Get user error:",
                error
            );

            return res.status(500).json({
                message:
                    "Failed to retrieve user."
            });
        }
    }
);

// ==========================================================
// SEND OTP EMAIL
// ==========================================================

async function sendOTPEmail(
    email,
    name,
    otp
) {
    const mailOptions = {
        from:
            `"RISX GTI" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,

        to: email,

        subject:
            "RISX GTI - Email Verification OTP",

        html: `
            <div style="
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: auto;
                padding: 30px;
                background: #0b1020;
                color: white;
                border-radius: 15px;
            ">

                <h1 style="
                    color: #00e5ff;
                    text-align: center;
                ">
                    RISX GTI
                </h1>

                <h2>
                    Verify Your Email
                </h2>

                <p>
                    Hello ${escapeHtml(name)},
                </p>

                <p>
                    Your verification OTP is:
                </p>

                <div style="
                    text-align: center;
                    margin: 30px 0;
                ">

                    <span style="
                        display: inline-block;
                        padding: 15px 30px;
                        background: #111a35;
                        color: #00e5ff;
                        font-size: 32px;
                        font-weight: bold;
                        letter-spacing: 8px;
                        border-radius: 10px;
                    ">
                        ${otp}
                    </span>

                </div>

                <p>
                    This OTP will expire in
                    <strong>10 minutes</strong>.
                </p>

                <p style="
                    color: #aaa;
                    font-size: 13px;
                ">
                    If you did not request this verification,
                    you can safely ignore this email.
                </p>

                <hr style="
                    border: none;
                    border-top: 1px solid #333;
                    margin: 25px 0;
                ">

                <p style="
                    text-align: center;
                    color: #777;
                ">
                    RISX GTI • Secure • Recover • Grow
                </p>

            </div>
        `
    };

    await transporter.sendMail(
        mailOptions
    );
}

// ==========================================================
// ESCAPE HTML
// ==========================================================

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==========================================================
// EXPORT
// ==========================================================

module.exports = router;
