export default function authorizeRoleMiddleware(role) {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      console.log("authorizeRoleMiddleware: доступ разрешён");
      next();
    } else {
      console.log("authorizeRoleMiddleware: доступ запрещён");
      return res.status(403).json({
        message: "Forbidden: You don't have access to this resource.",
      });
    }
  };
}
