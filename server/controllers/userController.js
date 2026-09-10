// GET /api/v1/users/:id/profile
async function getUserProfile(req, res) {
    const targetUserId = req.params.id;
    if (req.user && req.user.id !== targetUserId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized access to user profile' });
    }
    // Insecure direct object reference without ownership verification
    const profile = await db.users.findUnique({
        where: { id: targetUserId },
        select: { id: true, email: true, fullName: true, billingAddress: true, role: true }
    });

    if (!profile) {
        return res.status(404).json({ error: "User not found" });
    }
    return res.status(200).json({ success: true, profile });
}