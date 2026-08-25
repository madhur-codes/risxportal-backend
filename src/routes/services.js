const express = require("express");

const prisma = require("../lib/prisma");
const requireAdmin = require("../middleware/admin");

const router = express.Router();


// ==========================================================
// FORM SCHEMA VALIDATION
// ==========================================================

function validateFormSchema(formSchema) {
    if (formSchema === null || formSchema === undefined) {
        return {
            valid: true,
            value: null
        };
    }

    if (!Array.isArray(formSchema)) {
        return {
            valid: false,
            message: "formSchema must be an array."
        };
    }

    const allowedTypes = [
        "text",
        "email",
        "number",
        "tel",
        "textarea",
        "select",
        "password",
        "url",
        "date"
    ];

    const allowedKeys = [
        "name",
        "label",
        "type",
        "placeholder",
        "required",
        "options",
        "min",
        "max",
        "step"
    ];

    for (let i = 0; i < formSchema.length; i++) {
        const field = formSchema[i];

        if (!field || typeof field !== "object" || Array.isArray(field)) {
            return {
                valid: false,
                message: `Invalid form field at position ${i + 1}.`
            };
        }

        if (!field.name || typeof field.name !== "string") {
            return {
                valid: false,
                message: `Form field ${i + 1} must have a name.`
            };
        }

        if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(field.name)) {
            return {
                valid: false,
                message:
                    `Invalid field name "${field.name}". Use letters, numbers, _ or -.`
            };
        }

        if (!field.label || typeof field.label !== "string") {
            return {
                valid: false,
                message: `Form field "${field.name}" must have a label.`
            };
        }

        if (!field.type || typeof field.type !== "string") {
            return {
                valid: false,
                message: `Form field "${field.name}" must have a type.`
            };
        }

        if (!allowedTypes.includes(field.type)) {
            return {
                valid: false,
                message:
                    `Invalid field type "${field.type}" for "${field.name}".`
            };
        }

        if (
            field.required !== undefined &&
            typeof field.required !== "boolean"
        ) {
            return {
                valid: false,
                message:
                    `The required property for "${field.name}" must be true or false.`
            };
        }

        if (field.placeholder !== undefined &&
            typeof field.placeholder !== "string") {
            return {
                valid: false,
                message:
                    `Placeholder for "${field.name}" must be a string.`
            };
        }

        if (field.type === "select") {
            if (!Array.isArray(field.options)) {
                return {
                    valid: false,
                    message:
                        `Select field "${field.name}" must contain an options array.`
                };
            }

            for (const option of field.options) {
                if (
                    typeof option !== "string" &&
                    (
                        !option ||
                        typeof option !== "object"
                    )
                ) {
                    return {
                        valid: false,
                        message:
                            `Invalid option in select field "${field.name}".`
                    };
                }
            }
        }

        if (field.min !== undefined && typeof field.min !== "number") {
            return {
                valid: false,
                message:
                    `Minimum value for "${field.name}" must be a number.`
            };
        }

        if (field.max !== undefined && typeof field.max !== "number") {
            return {
                valid: false,
                message:
                    `Maximum value for "${field.name}" must be a number.`
            };
        }

        if (field.step !== undefined && typeof field.step !== "number") {
            return {
                valid: false,
                message:
                    `Step value for "${field.name}" must be a number.`
            };
        }

        for (const key of Object.keys(field)) {
            if (!allowedKeys.includes(key)) {
                return {
                    valid: false,
                    message:
                        `Unknown property "${key}" in form field "${field.name}".`
                };
            }
        }
    }

    const names = formSchema.map(field => field.name);

    if (new Set(names).size !== names.length) {
        return {
            valid: false,
            message: "Form field names must be unique."
        };
    }

    return {
        valid: true,
        value: formSchema
    };
}


// ==========================================================
// GET ALL ACTIVE SERVICES
// PUBLIC
// GET /api/services
// ==========================================================

router.get("/", async (req, res) => {
    try {
        const services = await prisma.service.findMany({
            where: {
                active: true
            },
            orderBy: {
                createdAt: "desc"
            }
        });

        res.json({
            services
        });

    } catch (error) {
        console.error("Get services error:", error);

        res.status(500).json({
            message: "Failed to fetch services."
        });
    }
});


// ==========================================================
// GET SINGLE ACTIVE SERVICE
// PUBLIC
// GET /api/services/:id
// ==========================================================

router.get("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id)) {
            return res.status(400).json({
                message: "Invalid service ID."
            });
        }

        const service = await prisma.service.findUnique({
            where: {
                id
            }
        });

        if (!service || !service.active) {
            return res.status(404).json({
                message: "Service not found."
            });
        }

        res.json({
            service
        });

    } catch (error) {
        console.error("Get service error:", error);

        res.status(500).json({
            message: "Failed to fetch service."
        });
    }
});


// ==========================================================
// GET ALL SERVICES
// ADMIN
// GET /api/services/admin/all
// ==========================================================

router.get("/admin/all", requireAdmin, async (req, res) => {
    try {
        const services = await prisma.service.findMany({
            orderBy: {
                createdAt: "desc"
            }
        });

        res.json({
            services
        });

    } catch (error) {
        console.error("Get admin services error:", error);

        res.status(500).json({
            message: "Failed to fetch services."
        });
    }
});


// ==========================================================
// CREATE SERVICE
// ADMIN
// POST /api/services
// ==========================================================

router.post("/", requireAdmin, async (req, res) => {
    try {
        const {
            name,
            description,
            price,
            active,
            formSchema
        } = req.body;

        if (!name || typeof name !== "string") {
            return res.status(400).json({
                message: "Service name is required."
            });
        }

        if (price === undefined || price === null || price === "") {
            return res.status(400).json({
                message: "Service price is required."
            });
        }

        const numericPrice = Number(price);

        if (
            !Number.isFinite(numericPrice) ||
            numericPrice < 0
        ) {
            return res.status(400).json({
                message:
                    "Price must be a valid non-negative number."
            });
        }

        const schemaResult =
            validateFormSchema(formSchema);

        if (!schemaResult.valid) {
            return res.status(400).json({
                message: schemaResult.message
            });
        }

        const service = await prisma.service.create({
            data: {
                name: name.trim(),

                description:
                    description &&
                    typeof description === "string"
                        ? description.trim()
                        : null,

                price: numericPrice,

                active:
                    active !== undefined
                        ? Boolean(active)
                        : true,

                formSchema: schemaResult.value
            }
        });

        res.status(201).json({
            message: "Service created successfully.",
            service
        });

    } catch (error) {
        console.error("Create service error:", error);

        res.status(500).json({
            message: "Failed to create service."
        });
    }
});


// ==========================================================
// UPDATE SERVICE
// ADMIN
// PUT /api/services/:id
// PATCH /api/services/:id
// ==========================================================

async function updateService(req, res) {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id)) {
            return res.status(400).json({
                message: "Invalid service ID."
            });
        }

        const existingService =
            await prisma.service.findUnique({
                where: {
                    id
                }
            });

        if (!existingService) {
            return res.status(404).json({
                message: "Service not found."
            });
        }

        const {
            name,
            description,
            price,
            active,
            formSchema
        } = req.body;

        const data = {};

        if (name !== undefined) {
            if (
                typeof name !== "string" ||
                !name.trim()
            ) {
                return res.status(400).json({
                    message:
                        "Service name cannot be empty."
                });
            }

            data.name = name.trim();
        }

        if (description !== undefined) {
            data.description =
                description &&
                typeof description === "string"
                    ? description.trim()
                    : null;
        }

        if (price !== undefined) {
            const numericPrice = Number(price);

            if (
                !Number.isFinite(numericPrice) ||
                numericPrice < 0
            ) {
                return res.status(400).json({
                    message:
                        "Price must be a valid non-negative number."
                });
            }

            data.price = numericPrice;
        }

        if (active !== undefined) {
            data.active = Boolean(active);
        }

        if (formSchema !== undefined) {
            const schemaResult =
                validateFormSchema(formSchema);

            if (!schemaResult.valid) {
                return res.status(400).json({
                    message: schemaResult.message
                });
            }

            data.formSchema = schemaResult.value;
        }

        const service =
            await prisma.service.update({
                where: {
                    id
                },
                data
            });

        res.json({
            message:
                "Service updated successfully.",
            service
        });

    } catch (error) {
        console.error("Update service error:", error);

        res.status(500).json({
            message: "Failed to update service."
        });
    }
}


router.put(
    "/:id",
    requireAdmin,
    updateService
);

router.patch(
    "/:id",
    requireAdmin,
    updateService
);


// ==========================================================
// DELETE SERVICE
// ADMIN
// DELETE /api/services/:id
// ==========================================================

router.delete("/:id", requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id)) {
            return res.status(400).json({
                message: "Invalid service ID."
            });
        }

        const service =
            await prisma.service.findUnique({
                where: {
                    id
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
                    serviceId: id
                }
            });

        if (orderCount > 0) {
            return res.status(409).json({
                message:
                    "This service has existing orders. Deactivate it instead of deleting it."
            });
        }

        await prisma.service.delete({
            where: {
                id
            }
        });

        res.json({
            message:
                "Service deleted successfully."
        });

    } catch (error) {
        console.error("Delete service error:", error);

        res.status(500).json({
            message: "Failed to delete service."
        });
    }
});


module.exports = router;