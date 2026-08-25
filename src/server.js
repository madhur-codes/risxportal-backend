require("dotenv").config();

const express = require("express");
const cors = require("cors");

const prisma = require("./lib/prisma");

const serviceRoutes = require("./routes/services");
const orderRoutes = require("./routes/orders");
const authRoutes = require("./routes/auth");
const paymentRoutes = require("./routes/payment");
const adminRoutes = require("./routes/admin");

const app = express();

const PORT = process.env.PORT || 5000;


// ==========================================================
// MIDDLEWARE
// ==========================================================

app.use(cors());
app.use(express.json());


// ==========================================================
// ROUTES
// ==========================================================

app.use("/api/payment", paymentRoutes);
app.use("/api/services", serviceRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/orders", orderRoutes);
app.use("/api/admin", adminRoutes);


// ==========================================================
// ROOT
// ==========================================================

app.get("/", (req, res) => {
    res.json({
        message: "RISXPortal Backend is running 🚀"
    });
});


// ==========================================================
// HEALTH CHECK
// ==========================================================

app.get("/api/health", async (req, res) => {
    try {
        await prisma.$queryRaw`SELECT 1`;

        res.json({
            status: "OK",
            database: "connected",
            service: "RISXPortal API"
        });

    } catch (error) {

        console.error(
            "Database connection error:",
            error
        );

        res.status(500).json({
            status: "ERROR",
            database: "disconnected"
        });
    }
});


// ==========================================================
// START SERVER
// ==========================================================

app.listen(PORT, () => {
    console.log(
        `RISXPortal Backend running on port ${PORT}`
    );
});
