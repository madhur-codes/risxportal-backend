const express = require("express");

const prisma = require("../lib/prisma");
const authenticate = require("../middleware/auth");
const router = express.Router();


// ==========================================================
// ADMIN CHECK
// ==========================================================

function adminOnly(req, res, next) {

    if (!req.user) {
        return res.status(401).json({
            message: "Authentication required."
        });
    }

    if (req.user.role !== "ADMIN") {
        return res.status(403).json({
            message: "Admin access required."
        });
    }

    next();
}


// ==========================================================
// AUTHENTICATION + ADMIN PROTECTION
// ==========================================================

router.use(authenticate);
router.use(adminOnly);


// ==========================================================
// ADMIN DASHBOARD
// GET /api/admin/dashboard
// ==========================================================

router.get("/dashboard", async (req, res) => {

    try {

        const [
            totalUsers,
            totalOrders,
            pendingOrders,
            processingOrders,
            completedOrders,
            cancelledOrders,
            totalServices
        ] = await Promise.all([

            prisma.user.count(),

            prisma.order.count(),

            prisma.order.count({
                where: {
                    status: "PENDING"
                }
            }),

            prisma.order.count({
                where: {
                    status: "PROCESSING"
                }
            }),

            prisma.order.count({
                where: {
                    status: "COMPLETED"
                }
            }),

            prisma.order.count({
                where: {
                    status: "CANCELLED"
                }
            }),

            prisma.service.count({
                where: {
                    active: true
                }
            })

        ]);


        return res.json({

            success: true,

            statistics: {
                totalUsers,
                totalOrders,
                pendingOrders,
                processingOrders,
                completedOrders,
                cancelledOrders,
                totalServices
            }

        });

    } catch (error) {

        console.error(
            "Admin dashboard error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load admin dashboard."
        });
    }

});


// ==========================================================
// GET ALL ORDERS
// GET /api/admin/orders
// ==========================================================

router.get("/orders", async (req, res) => {

    try {

        const orders =
            await prisma.order.findMany({

                orderBy: {
                    createdAt: "desc"
                },

                include: {

                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            role: true
                        }
                    },

                    service: {
                        select: {
                            id: true,
                            name: true,
                            description: true,
                            price: true,
                            active: true
                        }
                    },

                    payment: true

                }

            });


        return res.json({

            success: true,
            orders

        });

    } catch (error) {

        console.error(
            "Admin orders error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load orders."
        });
    }

});


// ==========================================================
// GET SINGLE ORDER
// GET /api/admin/orders/:id
// ==========================================================

router.get("/orders/:id", async (req, res) => {

    try {

        const orderId =
            Number(req.params.id);


        if (!Number.isInteger(orderId)) {

            return res.status(400).json({
                message: "Invalid order ID."
            });

        }


        const order =
            await prisma.order.findUnique({

                where: {
                    id: orderId
                },

                include: {

                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            role: true
                        }
                    },

                    service: {
                        select: {
                            id: true,
                            name: true,
                            description: true,
                            price: true,
                            active: true
                        }
                    },

                    payment: true

                }

            });


        if (!order) {

            return res.status(404).json({
                message: "Order not found."
            });

        }


        return res.json({

            success: true,
            order

        });

    } catch (error) {

        console.error(
            "Get admin order error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load order."
        });
    }

});


// ==========================================================
// UPDATE ORDER STATUS
// PATCH /api/admin/orders/:id/status
// ==========================================================

router.patch(
    "/orders/:id/status",
    async (req, res) => {

        try {

            const orderId =
                Number(req.params.id);

            const { status } =
                req.body;


            if (!Number.isInteger(orderId)) {

                return res.status(400).json({
                    message: "Invalid order ID."
                });

            }


            const allowedStatuses = [
                "PENDING",
                "PROCESSING",
                "COMPLETED",
                "CANCELLED"
            ];


            if (
                !status ||
                !allowedStatuses.includes(status)
            ) {

                return res.status(400).json({

                    message:
                        "Invalid status. Allowed values: PENDING, PROCESSING, COMPLETED, CANCELLED."

                });

            }


            const existingOrder =
                await prisma.order.findUnique({

                    where: {
                        id: orderId
                    }

                });


            if (!existingOrder) {

                return res.status(404).json({
                    message: "Order not found."
                });

            }


            const updatedOrder =
                await prisma.order.update({

                    where: {
                        id: orderId
                    },

                    data: {
                        status
                    },

                    include: {

                        user: {
                            select: {
                                id: true,
                                name: true,
                                email: true,
                                role: true
                            }
                        },

                        service: {
                            select: {
                                id: true,
                                name: true,
                                description: true,
                                price: true,
                                active: true
                            }
                        },

                        payment: true

                    }

                });


            return res.json({

                success: true,

                message:
                    "Order status updated successfully.",

                order:
                    updatedOrder

            });

        } catch (error) {

            console.error(
                "Update order status error:",
                error
            );

            return res.status(500).json({
                message: "Failed to update order status."
            });
        }

    }
);


// ==========================================================
// GET ALL USERS
// GET /api/admin/users
// ==========================================================

router.get("/users", async (req, res) => {

    try {

        const users =
            await prisma.user.findMany({

                orderBy: {
                    createdAt: "desc"
                },

                select: {

                    id: true,

                    name: true,

                    email: true,

                    role: true,

                    createdAt: true,

                    updatedAt: true

                }

            });


        return res.json({

            success: true,
            users

        });

    } catch (error) {

        console.error(
            "Admin users error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load users."
        });
    }

});


// ==========================================================
// GET SINGLE USER
// GET /api/admin/users/:id
// ==========================================================

router.get("/users/:id", async (req, res) => {

    try {

        const userId =
            Number(req.params.id);


        if (!Number.isInteger(userId)) {

            return res.status(400).json({
                message: "Invalid user ID."
            });

        }


        const user =
            await prisma.user.findUnique({

                where: {
                    id: userId
                },

                select: {

                    id: true,

                    name: true,

                    email: true,

                    role: true,

                    createdAt: true,

                    updatedAt: true,

                    orders: {

                        orderBy: {
                            createdAt: "desc"
                        },

                        include: {

                            service: true,

                            payment: true

                        }

                    }

                }

            });


        if (!user) {

            return res.status(404).json({
                message: "User not found."
            });

        }


        return res.json({

            success: true,
            user

        });

    } catch (error) {

        console.error(
            "Get admin user error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load user."
        });
    }

});


// ==========================================================
// GET ALL SERVICES
// GET /api/admin/services
// ==========================================================

router.get("/services", async (req, res) => {

    try {

        const services =
            await prisma.service.findMany({

                orderBy: {
                    id: "desc"
                }

            });


        return res.json({

            success: true,
            services

        });

    } catch (error) {

        console.error(
            "Admin services error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load services."
        });
    }

});


// ==========================================================
// CREATE SERVICE
// POST /api/admin/services
// ==========================================================

router.post("/services", async (req, res) => {

    try {

        const {
            name,
            description,
            price
        } = req.body;


        if (!name || price === undefined) {

            return res.status(400).json({
                message:
                    "Service name and price are required."
            });

        }


        const cleanName =
            String(name).trim();


        if (!cleanName) {

            return res.status(400).json({
                message:
                    "Service name cannot be empty."
            });

        }


        const numericPrice =
            Number(price);


        if (
            !Number.isFinite(numericPrice) ||
            numericPrice < 0
        ) {

            return res.status(400).json({
                message: "Invalid service price."
            });

        }


        const service =
            await prisma.service.create({

                data: {

                    name:
                        cleanName,

                    description:
                        description !== undefined &&
                        description !== null
                            ? String(description).trim()
                            : "",

                    price:
                        numericPrice,

                    active:
                        true

                }

            });


        return res.status(201).json({

            success: true,

            message:
                "Service created successfully.",

            service

        });

    } catch (error) {

        console.error(
            "Create service error:",
            error
        );

        return res.status(500).json({
            message: "Failed to create service."
        });
    }

});


// ==========================================================
// UPDATE SERVICE
// PATCH /api/admin/services/:id
// ==========================================================

router.patch(
    "/services/:id",
    async (req, res) => {

        try {

            const serviceId =
                Number(req.params.id);


            if (!Number.isInteger(serviceId)) {

                return res.status(400).json({
                    message: "Invalid service ID."
                });

            }


            const {
                name,
                description,
                price,
                active
            } = req.body;


            const existingService =
                await prisma.service.findUnique({

                    where: {
                        id: serviceId
                    }

                });


            if (!existingService) {

                return res.status(404).json({
                    message: "Service not found."
                });

            }


            const data = {};


            if (name !== undefined) {

                const cleanName =
                    String(name).trim();


                if (!cleanName) {

                    return res.status(400).json({
                        message:
                            "Service name cannot be empty."
                    });

                }


                data.name =
                    cleanName;

            }


            if (description !== undefined) {

                data.description =
                    String(description).trim();

            }


            if (price !== undefined) {

                const numericPrice =
                    Number(price);


                if (
                    !Number.isFinite(numericPrice) ||
                    numericPrice < 0
                ) {

                    return res.status(400).json({
                        message:
                            "Invalid service price."
                    });

                }


                data.price =
                    numericPrice;

            }


            if (active !== undefined) {

                if (
                    typeof active !== "boolean"
                ) {

                    return res.status(400).json({
                        message:
                            "Active must be true or false."
                    });

                }


                data.active =
                    active;

            }


            const service =
                await prisma.service.update({

                    where: {
                        id: serviceId
                    },

                    data

                });


            return res.json({

                success: true,

                message:
                    "Service updated successfully.",

                service

            });

        } catch (error) {

            console.error(
                "Update service error:",
                error
            );

            return res.status(500).json({
                message: "Failed to update service."
            });
        }

    }
);


// ==========================================================
// DELETE SERVICE
// DELETE /api/admin/services/:id
// ==========================================================

router.delete(
    "/services/:id",
    async (req, res) => {

        try {

            const serviceId =
                Number(req.params.id);


            if (!Number.isInteger(serviceId)) {

                return res.status(400).json({
                    message: "Invalid service ID."
                });

            }


            const service =
                await prisma.service.findUnique({

                    where: {
                        id: serviceId
                    }

                });


            if (!service) {

                return res.status(404).json({
                    message: "Service not found."
                });

            }


            const orderCount =
                await prisma.order.count({

                    where: {
                        serviceId
                    }

                });


            if (orderCount > 0) {

                return res.status(400).json({

                    message:
                        "This service cannot be deleted because orders already exist for it."

                });

            }


            await prisma.service.delete({

                where: {
                    id: serviceId
                }

            });


            return res.json({

                success: true,

                message:
                    "Service deleted successfully."

            });

        } catch (error) {

            console.error(
                "Delete service error:",
                error
            );

            return res.status(500).json({
                message: "Failed to delete service."
            });
        }

    }
);


// ==========================================================
// ADMIN PROFILE
// GET /api/admin/profile
// ==========================================================

router.get("/profile", async (req, res) => {

    try {

        const admin =
            await prisma.user.findUnique({

                where: {
                    id: req.user.id || req.user.userId
                },

                select: {

                    id: true,

                    name: true,

                    email: true,

                    role: true,

                    createdAt: true,

                    updatedAt: true

                }

            });


        if (!admin) {

            return res.status(404).json({
                message: "Admin user not found."
            });

        }


        return res.json({

            success: true,
            user: admin

        });

    } catch (error) {

        console.error(
            "Admin profile error:",
            error
        );

        return res.status(500).json({
            message: "Failed to load admin profile."
        });
    }

});


// ==========================================================
// EXPORT
// ==========================================================

module.exports = router;
