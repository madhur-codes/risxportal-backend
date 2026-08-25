const express = require("express");
const crypto = require("crypto");

const prisma = require("../lib/prisma");
const razorpay = require("../lib/razorpay");

const authenticate = require("../middleware/auth");
const requireAdmin = require("../middleware/admin");

const router = express.Router();


// ======================================================
// CREATE ORDER
// POST /api/orders
// ======================================================

router.post("/", authenticate, async (req, res) => {

    try {

        const {
            serviceId,
            quantity = 1,
            customerDetails
        } = req.body;


        const parsedServiceId =
            Number(serviceId);

        const parsedQuantity =
            Number(quantity);


        // --------------------------------------------------
        // VALIDATE SERVICE
        // --------------------------------------------------

        if (!Number.isInteger(parsedServiceId)) {

            return res.status(400).json({
                message: "Invalid service ID."
            });

        }


        if (
            !Number.isInteger(parsedQuantity) ||
            parsedQuantity < 1
        ) {

            return res.status(400).json({
                message:
                    "Quantity must be a positive integer."
            });

        }


        // --------------------------------------------------
        // VALIDATE CUSTOMER DETAILS
        // --------------------------------------------------

        if (!customerDetails) {

            return res.status(400).json({
                message:
                    "Customer details are required."
            });

        }


        const name =
            String(customerDetails.name || "").trim();

        const mobile =
            String(customerDetails.mobile || "").trim();

        const instagramUsername =
            String(
                customerDetails.instagramUsername || ""
            ).trim();

        const email =
            String(customerDetails.email || "")
                .trim()
                .toLowerCase();


        if (!name) {

            return res.status(400).json({
                message: "Name is required."
            });

        }


        if (!mobile) {

            return res.status(400).json({
                message: "Mobile number is required."
            });

        }


        if (!instagramUsername) {

            return res.status(400).json({
                message:
                    "Instagram username is required."
            });

        }


        if (!email) {

            return res.status(400).json({
                message: "Email address is required."
            });

        }


        // --------------------------------------------------
        // FIND SERVICE
        // --------------------------------------------------

        const service =
            await prisma.service.findUnique({

                where: {
                    id: parsedServiceId
                }

            });


        if (!service || !service.active) {

            return res.status(404).json({
                message:
                    "Service not found or unavailable."
            });

        }


        // --------------------------------------------------
        // CALCULATE TOTAL SERVER-SIDE
        // --------------------------------------------------

        const totalAmount =
            Number(service.price) *
            parsedQuantity;


        // --------------------------------------------------
        // CREATE ORDER NUMBER
        // --------------------------------------------------

        const orderNumber =
            `RISX-${Date.now()}-${Math.floor(
                Math.random() * 10000
            )}`;


        // --------------------------------------------------
        // CREATE DATABASE ORDER
        // --------------------------------------------------

        const order =
            await prisma.order.create({

                data: {

                    orderNumber,

                    userId:
                        req.user.userId,

                    serviceId:
                        parsedServiceId,

                    quantity:
                        parsedQuantity,

                    totalAmount,

                    customerDetails: {

                        name,

                        mobile,

                        instagramUsername,

                        email

                    }

                },

                include: {

                    service: true

                }

            });


        // --------------------------------------------------
        // CREATE RAZORPAY ORDER
        // --------------------------------------------------

        const razorpayOrder =
            await razorpay.orders.create({

                amount:
                    Math.round(
                        totalAmount * 100
                    ),

                currency:
                    "INR",

                receipt:
                    order.orderNumber,

                notes: {

                    risxOrderId:
                        String(order.id),

                    serviceId:
                        String(parsedServiceId)

                }

            });


        // --------------------------------------------------
        // CREATE PAYMENT RECORD
        // --------------------------------------------------

        await prisma.payment.create({

            data: {

                orderId:
                    order.id,

                amount:
                    totalAmount,

                status:
                    "PENDING",

                provider:
                    "RAZORPAY"

            }

        });


        return res.status(201).json({

            success: true,

            order: {

                id:
                    order.id,

                orderNumber:
                    order.orderNumber,

                totalAmount:
                    order.totalAmount,

                service:
                    order.service

            },

            razorpay: {

                orderId:
                    razorpayOrder.id,

                amount:
                    razorpayOrder.amount,

                currency:
                    razorpayOrder.currency

            }

        });

    } catch (error) {

        console.error(
            "Create order error:",
            error
        );

        return res.status(500).json({

            message:
                "Failed to create order."

        });

    }

});


// ======================================================
// VERIFY RAZORPAY PAYMENT
// POST /api/orders/payment/verify
// ======================================================

router.post(
    "/payment/verify",
    authenticate,
    async (req, res) => {

        try {

            const {
                razorpay_order_id,
                razorpay_payment_id,
                razorpay_signature,
                orderId
            } = req.body;


            if (
                !razorpay_order_id ||
                !razorpay_payment_id ||
                !razorpay_signature ||
                !orderId
            ) {

                return res.status(400).json({

                    message:
                        "Payment verification data is incomplete."

                });

            }


            const order =
                await prisma.order.findUnique({

                    where: {
                        id: Number(orderId)
                    },

                    include: {
                        payment: true
                    }

                });


            if (!order) {

                return res.status(404).json({

                    message:
                        "Order not found."

                });

            }


            if (
                order.userId !==
                req.user.userId
            ) {

                return res.status(403).json({

                    message:
                        "You cannot verify this order."

                });

            }


            // --------------------------------------------------
            // VERIFY SIGNATURE
            // --------------------------------------------------

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


            const signatureMatches =
                crypto.timingSafeEqual(

                    Buffer.from(
                        generatedSignature
                    ),

                    Buffer.from(
                        razorpay_signature
                    )

                );


            if (!signatureMatches) {

                if (order.payment) {

                    await prisma.payment.update({

                        where: {
                            orderId:
                                order.id
                        },

                        data: {

                            status:
                                "FAILED"

                        }

                    });

                }


                return res.status(400).json({

                    message:
                        "Payment verification failed."

                });

            }


            // --------------------------------------------------
            // MARK PAYMENT PAID
            // --------------------------------------------------

            await prisma.$transaction([

                prisma.payment.update({

                    where: {

                        orderId:
                            order.id

                    },

                    data: {

                        status:
                            "PAID",

                        transactionId:
                            razorpay_payment_id,

                        provider:
                            "RAZORPAY"

                    }

                }),

                prisma.order.update({

                    where: {

                        id:
                            order.id

                    },

                    data: {

                        status:
                            "PROCESSING"

                    }

                })

            ]);


            return res.json({

                success: true,

                message:
                    "Payment verified successfully.",

                orderId:
                    order.id,

                orderNumber:
                    order.orderNumber

            });

        } catch (error) {

            console.error(
                "Payment verification error:",
                error
            );

            return res.status(500).json({

                message:
                    "Failed to verify payment."

            });

        }

    }
);


// ======================================================
// GET MY ORDERS
// GET /api/orders/my
// ======================================================

router.get(
    "/my",
    authenticate,
    async (req, res) => {

        try {

            const orders =
                await prisma.order.findMany({

                    where: {

                        userId:
                            req.user.userId

                    },

                    include: {

                        service: true,

                        payment: true

                    },

                    orderBy: {

                        createdAt:
                            "desc"

                    }

                });


            return res.json({

                success: true,

                orders

            });

        } catch (error) {

            console.error(
                "Get my orders error:",
                error
            );

            return res.status(500).json({

                message:
                    "Failed to fetch orders."

            });

        }

    }
);


// ======================================================
// GET ALL ORDERS
// GET /api/orders/admin/all
// ======================================================

router.get(
    "/admin/all",
    requireAdmin,
    async (req, res) => {

        try {

            const orders =
                await prisma.order.findMany({

                    include: {

                        user: {

                            select: {

                                id: true,
                                name: true,
                                email: true

                            }

                        },

                        service: true,

                        payment: true

                    },

                    orderBy: {

                        createdAt:
                            "desc"

                    }

                });


            return res.json({

                success: true,

                orders

            });

        } catch (error) {

            console.error(
                "Get all orders error:",
                error
            );

            return res.status(500).json({

                message:
                    "Failed to fetch orders."

            });

        }

    }
);


// ======================================================
// GET SINGLE ORDER
// GET /api/orders/:id
// ======================================================

router.get(
    "/:id",
    authenticate,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);


            if (!Number.isInteger(id)) {

                return res.status(400).json({

                    message:
                        "Invalid order ID."

                });

            }


            const order =
                await prisma.order.findFirst({

                    where: {

                        id,

                        userId:
                            req.user.userId

                    },

                    include: {

                        service: true,

                        payment: true

                    }

                });


            if (!order) {

                return res.status(404).json({

                    message:
                        "Order not found."

                });

            }


            return res.json({

                success: true,

                order

            });

        } catch (error) {

            console.error(
                "Get order error:",
                error
            );

            return res.status(500).json({

                message:
                    "Failed to fetch order."

            });

        }

    }
);


// ======================================================
// UPDATE ORDER STATUS
// PATCH /api/orders/:id/status
// ======================================================

router.patch(
    "/:id/status",
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const {
                status
            } = req.body;


            const allowedStatuses = [

                "PENDING",
                "PROCESSING",
                "COMPLETED",
                "CANCELLED"

            ];


            if (!Number.isInteger(id)) {

                return res.status(400).json({

                    message:
                        "Invalid order ID."

                });

            }


            if (
                !allowedStatuses.includes(status)
            ) {

                return res.status(400).json({

                    message:
                        "Invalid order status."

                });

            }


            const order =
                await prisma.order.update({

                    where: {
                        id
                    },

                    data: {
                        status
                    },

                    include: {

                        user: true,

                        service: true,

                        payment: true

                    }

                });


            return res.json({

                success: true,

                message:
                    "Order status updated successfully.",

                order

            });

        } catch (error) {

            console.error(
                "Update order status error:",
                error
            );

            return res.status(500).json({

                message:
                    "Failed to update order status."

            });

        }

    }
);


module.exports = router;
