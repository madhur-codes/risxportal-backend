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

const smtpHost = process.env.SMTP_HOST || "smtp.gmail.com";
const smtpPort = Number(process.env.SMTP_PORT || 465);

const smtpSecure =
    process.env.SMTP_SECURE !== undefined
        ? process.env.SMTP_SECURE === "true"
        : smtpPort === 465;

const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

transporter
    .verify()
    .then(() => {
        console.log("✅ SMTP server is ready to send emails");
    })
    .catch((error) => {
        console.error(
            "❌ SMTP configuration error:",
            error.message
        );
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

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==========================================================
// SEND OTP EMAIL
// IMPORTANT: ONLY ONE sendOTPEmail FUNCTION IN THIS FILE
// ==========================================================

async function sendOTPEmail(email, name, otp) {
    if (!process.env.SMTP_USER) {
        throw new Error("SMTP_USER is missing.");
    }

    if (!process.env.SMTP_PASS) {
        throw new Error("SMTP_PASS is missing.");
    }

    const from =
        process.env.SMTP_FROM ||
        `"RISX GTI" <${process.env.SMTP_USER}>`;

    console.log("📨 Sending OTP email to:", email);

    const info = await transporter.sendMail({
        from,
        to: email,
        subject: "RISX GTI - Email Verification OTP",

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
    });

    console.log(
        "📧 Email accepted by SMTP:",
        info.messageId
    );

    return info;
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
        } = req.body || {};

        if (!name || !email || !password) {
            return res.status(400).json({
                message:
                    "Name, email and password are required."
            });
        }

        const cleanName = String(name).trim();

        const normalizedEmail =
            normalizeEmail(email);

        if (cleanName.length < 2) {
            return res.status(400).json({
                message:
                    "Please enter a valid name."
            });
        }

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({
                message:
                    "Please enter a valid email address."
            });
        }

        if (String(password).length < 6) {
            return res.status(400).json({
                message:
                    "Password must be at least 6 characters."
            });
        }

        console.log(
            "📝 Registration request:",
            normalizedEmail
        );

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
        // REMOVE OLD PENDING VERIFICATION
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
            await bcrypt.hash(
                String(password),
                12
            );

        // --------------------------------------------------
        // CREATE OTP
        // --------------------------------------------------

        const otp =
            generateOTP();

        const otpHash =
            hashOTP(otp);

        const expiresAt =
            new Date(
                Date.now() +
                10 * 60 * 1000
            );

        // --------------------------------------------------
        // SAVE VERIFICATION RECORD
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

        console.log(
            "✅ OTP verification record created:",
            normalizedEmail
        );

        // --------------------------------------------------
        // SEND OTP EMAIL
        // --------------------------------------------------

        try {
            await sendOTPEmail(
                normalizedEmail,
                cleanName,
                otp
            );
        } catch (emailError) {

            console.error(
                "❌ OTP email error:",
                emailError
            );

            // Remove pending verification if email failed
            await prisma.emailVerification.deleteMany({
                where: {
                    email: normalizedEmail
                }
            });

            return res.status(500).json({
                message:
                    "Unable to send verification email. Please check the server email configuration."
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
            "❌ Registration error:",
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
        } = req.body || {};

        if (!email || !otp) {
            return res.status(400).json({
                message:
                    "Email and OTP are required."
            });
        }

        const normalizedEmail =
            normalizeEmail(email);

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
        // VERIFY OTP
        // --------------------------------------------------

        const submittedHash =
            hashOTP(
                String(otp).trim()
            );

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
        // CHECK IF USER ALREADY EXISTS
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

        console.log(
            "✅ User verified and created:",
            user.email
        );

        return res.status(200).json({
            message:
                "Email verified successfully.",

            token,

            user
        });

    } catch (error) {

        console.error(
            "❌ OTP verification error:",
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

        const { email } =
            req.body || {};

        if (!email) {
            return res.status(400).json({
                message:
                    "Email is required."
            });
        }

        const normalizedEmail =
            normalizeEmail(email);

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
        // CREATE NEW OTP
        // --------------------------------------------------

        const otp =
            generateOTP();

        const otpHash =
            hashOTP(otp);

        const expiresAt =
            new Date(
                Date.now() +
                10 * 60 * 1000
            );

        // --------------------------------------------------
        // SEND EMAIL FIRST
        // --------------------------------------------------

        try {

            await sendOTPEmail(
                normalizedEmail,
                verification.name,
                otp
            );

        } catch (emailError) {

            console.error(
                "❌ Resend OTP email error:",
                emailError
            );

            return res.status(500).json({
                message:
                    "Unable to resend OTP. Please check the server email configuration."
            });
        }

        // --------------------------------------------------
        // UPDATE OTP
        // --------------------------------------------------

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

        console.log(
            "✅ OTP resent:",
            normalizedEmail
        );

        return res.json({
            message:
                "A new OTP has been sent to your email."
        });

    } catch (error) {

        console.error(
            "❌ Resend OTP error:",
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
        } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({
                message:
                    "Email and password are required."
            });
        }

        const normalizedEmail =
            normalizeEmail(email);

        // --------------------------------------------------
        // FIND USER
        // --------------------------------------------------

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

        // --------------------------------------------------
        // CHECK PASSWORD
        // --------------------------------------------------

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

        // --------------------------------------------------
        // CREATE TOKEN
        // --------------------------------------------------

        const token =
            createToken(user);

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

// ==========================================================
// EXPORT
// ==========================================================

module.exports = router;
