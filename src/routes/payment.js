const express = require("express");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const prisma = require("../lib/prisma");

const router = express.Router();

// ======================================================
// RAZORPAY CONFIG
// ======================================================

if (!process.env.RAZORPAY_KEY_ID) {
    console.error("❌ RAZORPAY_KEY_ID is missing from .env");
}

if (!process.env.RAZORPAY_KEY_SECRET) {
    console.error("❌ RAZORPAY_KEY_SECRET is missing from .env");
}

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});


// ======================================================
// CREATE RAZORPAY ORDER
// ======================================================

router.post("/create-order", async (req, res) => {
    try {
        const { orderId } = req.body;

        if (!orderId) {
            return res.status(400).json({
                message: "Order ID is required."
            });
        }

        const order = await prisma.order.findUnique({
            where: {
                id: Number(orderId)
            },
            include: {
                payment: true,
                service: true
            }
        });

        if (!order) {
            return res.status(404).json({
                message: "Order not found."
            });
        }

        // Prevent creating another payment order
        if (order.payment?.status === "PAID") {
            return res.status(400).json({
                message: "This order has already been paid."
            });
        }

        const amount = Math.round(
            Number(order.totalAmount) * 100
        );

        if (!amount || amount <= 0) {
            return res.status(400).json({
                message: "Invalid order amount."
            });
        }

        const razorpayOrder =
            await razorpay.orders.create({
                amount,
                currency: "INR",
                receipt: order.orderNumber,
                notes: {
                    orderId: String(order.id),
                    orderNumber: order.orderNumber
                }
            });

        // Create or update payment record
        if (order.payment) {

            await prisma.payment.update({
                where: {
                    orderId: order.id
                },
                data: {
                    amount: order.totalAmount,
                    status: "PENDING",
                    provider: "RAZORPAY"
                }
            });

        } else {

            await prisma.payment.create({
                data: {
                    orderId: order.id,
                    amount: order.totalAmount,
                    status: "PENDING",
                    provider: "RAZORPAY"
                }
            });

        }

        res.json({
            success: true,
            razorpayOrderId: razorpayOrder.id,
            amount: razorpayOrder.amount,
            currency: razorpayOrder.currency,
            keyId: process.env.RAZORPAY_KEY_ID
        });

    } catch (error) {

        console.error(
            "Create Razorpay order error:",
            error
        );

        res.status(500).json({
            message: "Unable to create Razorpay order."
        });
    }
});


// ======================================================
// VERIFY PAYMENT
// ======================================================

router.post("/verify", async (req, res) => {
    try {

        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature
        } = req.body;

        if (
            !razorpay_order_id ||
            !razorpay_payment_id ||
            !razorpay_signature
        ) {
            return res.status(400).json({
                message: "Missing payment verification details."
            });
        }

        const generatedSignature =
            crypto
                .createHmac(
                    "sha256",
                    process.env.RAZORPAY_KEY_SECRET
                )
                .update(
                    `${razorpay_order_id}|${razorpay_payment_id}`
                )
                .digest("hex");

        if (
            generatedSignature !==
            razorpay_signature
        ) {
            return res.status(400).json({
                message: "Invalid payment signature."
            });
        }

        const razorpayOrder =
            await razorpay.orders.fetch(
                razorpay_order_id
            );

        const orderId =
            Number(
                razorpayOrder.notes?.orderId
            );

        if (!orderId) {
            return res.status(400).json({
                message: "Unable to identify RISX order."
            });
        }

        const order =
            await prisma.order.findUnique({
                where: {
                    id: orderId
                },
                include: {
                    payment: true
                }
            });

        if (!order) {
            return res.status(404).json({
                message: "RISX order not found."
            });
        }

        await prisma.payment.update({
            where: {
                orderId: order.id
            },
            data: {
                status: "PAID",
                transactionId: razorpay_payment_id,
                provider: "RAZORPAY"
            }
        });

        await prisma.order.update({
            where: {
                id: order.id
            },
            data: {
                status: "PROCESSING"
            }
        });

        res.json({
            success: true,
            message: "Payment verified successfully."
        });

    } catch (error) {

        console.error(
            "Payment verification error:",
            error
        );

        res.status(500).json({
            message: "Payment verification failed."
        });
    }
});


// ======================================================
// GET PAYMENT DETAILS
// ======================================================

router.get("/:orderId", async (req, res) => {
    try {

        const orderId =
            Number(req.params.orderId);

        if (!Number.isInteger(orderId)) {
            return res.status(400).json({
                message: "Invalid order ID."
            });
        }

        const payment =
            await prisma.payment.findUnique({
                where: {
                    orderId
                }
            });

        if (!payment) {
            return res.status(404).json({
                message: "Payment not found."
            });
        }

        res.json({
            success: true,
            payment
        });

    } catch (error) {

        console.error(
            "Get payment error:",
            error
        );

        res.status(500).json({
            message: "Unable to fetch payment."
        });
    }
});


module.exports = router;
