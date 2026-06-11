output "otpTtlSeconds" {
  value       = "otp.ttl.seconds"
  description = "Tiempo en segundos en el cual vence un OTP."
}
output "owner_email" {
  value       = "owner.email"
  description = "Email del dueno o contacto responsable."
}
output "type" {
  value       = "custom_type"
  description = "Tipo segun estandares definidos por equipo IDP."
}
output "category" {
  value       = "category"
  description = "Categoria a la que pertenece."
}

output "disabledDate" {
  value       = "disabled_date"
  description = "Fecha de deshabilitacion (formato yyyy-MM-dd)."
}