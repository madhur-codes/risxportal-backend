const prisma = require("../lib/prisma");
const { authenticate } = require("./auth");

async function requireAdmin(req, res, next) {
    try {
        await authenticate(req, res, async () => {

            if (!req.user) {
                return res.status(401).json({
                    message: "Authentication required."
                });
            }

            const user = await prisma.user.findUnique({
                where: {
                    id: req.user.userId
                },
                select: {
                    id: true,
                    role: true
                }
            });

            if (!user) {
                return res.status(401).json({
                    message: "User not found."
                });
            }

            if (user.role !== "ADMIN") {
                return res.status(403).json({
                    message: "Admin access required."
                });
            }

            req.user.role = user.role;

            next();
        });

    } catch (error) {
        console.error("Admin middleware error:", error);

        return res.status(500).json({
            message: "Authentication failed."
        });
    }
}

module.exports = requireAdmin;
