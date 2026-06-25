#!/usr/bin/env Rscript
# fwknop-client.R — tiny fwknop SPA client in R
#
# Sends a Single Packet Authorization (SPA) UDP packet to an fwknopd server.
#
# Protocol pipeline:
#   rand:user:ts:ver:type:msg → SHA-256 → AES-256-CBC (OpenSSL "Salted__" format)
#   → optional HMAC-SHA256 appended → UDP payload
#
# Required packages: digest, openssl, base64enc
#   install.packages(c("digest", "openssl", "base64enc"))

# suppressPackageStartupMessages({
#   for (pkg in c("digest", "openssl", "base64enc", "keyring")) {
#     if (!requireNamespace(pkg, quietly = TRUE)) install.packages(pkg)
#     library(pkg, character.only = TRUE)
#   }
#   for (pkg in c("udpprobe")) {
#     if (!requireNamespace(pkg, quietly = TRUE)) remotes::install_github("hrbrmstr/udpprobe")
#     library(pkg, character.only = TRUE)
#   }
# })


#' Send a Single Packet Authorization (SPA) request using the fwknop protocol
#'
#' Generates and sends an SPA packet to a remote fwknop server, allowing
#' temporary access through a firewall according to the specified access
#' request and server credentials.
#'
#' @param access_request Character string describing the access to request.
#'   The format depends on the fwknop server configuration (for example,
#'   `"tcp/22"` to request SSH access).
#' @param server_ip Character string containing the IPv4 or IPv6 address
#'   of the fwknop server.
#' @param server_port Integer or character string specifying the port on
#'   which the fwknop server is listening.
#' @param server_key Character string in BASE64 containing the encryption key used
#'   to encrypt the SPA packet.
#' @param server_hmac Character string in BASE64 containing the HMAC key used to
#'   authenticate the SPA packet.
#' @param verbose Logical. If `TRUE`, prints additional information about
#'   the SPA request and transmission process. Defaults to `FALSE`.
#'
#'
#' @details
#' This function acts as an R interface to the fwknop (FireWall KNock
#' OPerator) Single Packet Authorization system. The client generates an
#' encrypted and authenticated SPA packet that is sent to a remote fwknop
#' server, which may temporarily open firewall access for the requested
#' service.
#'
#' All server parameters can be supplied directly or obtained from
#' environment variables or configuration files if supported by the
#' implementation.
#'
#' @examples
#' \dontrun{
#' fwknop(
#'   access_request = "tcp/22",
#'   server_ip = "192.168.1.100",
#'   server_port = 62201,
#'   server_key = "my_encryption_key",
#'   server_hmac = "my_hmac_key",
#'   verbose = TRUE
#' )
#' }
#'
#' @importFrom keyring keyring_list
#' @importFrom keyring keyring_create
#' @importFrom keyring keyring_unlock
#' @importFrom keyring keyring_lock
#' @importFrom keyring key_set
#' @importFrom keyring key_get
#' @importFrom base64enc base64encode
#' @importFrom base64enc base64decode
#' @importFrom openssl md5
#' @importFrom openssl sha256
#' @importFrom openssl rand_bytes
#' @importFrom digest AES
#' @importFrom udpprobe udp_send_payload
#'
#' @export
fwknop <- function(access_request = NULL,
                   server_ip = NULL,
                   server_port = NULL,
                   server_key = NULL,
                   server_hmac = NULL,
                   verbose = FALSE) {

  KEYRING <- "spa_knock"
  if(!(KEYRING %in% keyring::keyring_list()$keyring)) {
    keyring::keyring_create(KEYRING)
    keyring::keyring_unlock(keyring = KEYRING)
    keyring::key_set(service = "SPA_SERVER", keyring = "spa_knock", prompt = "server IP")
    keyring::key_set(service = "SPA_PORT", keyring = "spa_knock", prompt = "server port")
    keyring::key_set(service = "SPA_KEY_BASE64", keyring = "spa_knock", prompt = "server key")
    keyring::key_set(service = "SPA_HMAC_KEY_BASE64", keyring = "spa_knock", prompt = "server hmac")
    #keyring::key_set(service = "SPA_ACCESS", keyring = "spa_knock", prompt = "access request")
    keyring::keyring_lock(keyring = KEYRING)
  }

  keyring::keyring_unlock(keyring = KEYRING)
  on.exit({keyring::keyring_lock(keyring = KEYRING)}, add = TRUE)

  if (is.null(server_ip)) {
    SPA_SERVER          <- keyring::key_get(service = "SPA_SERVER", keyring = "spa_knock")
  } else {
    if (is.null(server_ip)) {
      stop("no server_ip specified")
    }
  }
  if (is.null(server_port)) {
    SPA_PORT            <- keyring::key_get(service = "SPA_PORT", keyring = "spa_knock")
  } else {
    if (is.null(server_port)) {
      stop("no server_port specified")
    }
  }
  if (is.null(server_key)) {
    SPA_KEY_BASE64      <- keyring::key_get(service = "SPA_KEY_BASE64", keyring = "spa_knock")
  } else {
    if (is.null(server_key)) {
      stop("no server_key specified")
    }
  }
  if (is.null(server_hmac)) {
    SPA_HMAC_KEY_BASE64 <- keyring::key_get(service = "SPA_HMAC_KEY_BASE64", keyring = "spa_knock")
  } else {
    if (is.null(server_hmac)) {
      stop("no server_hmac specified")
    }
  }
  if (is.null(access_request)) {
    stop("no access_request specified")
  } else {
    SPA_ACCESS = access_request
  }

  # ── Helpers ────────────────────────────────────────────────────────────────────

  # Base64 encode raw bytes, no line-wrapping
  b64     <- function(raw_bytes) gsub("\n", "", base64enc::base64encode(raw_bytes))
  b64dec  <- function(s)         base64enc::base64decode(s)

  # Resolve key to a raw vector (decode base64 or convert string to raw)
  key_raw <- function(b64_val, str_val)
    if (!is.null(b64_val)) b64dec(b64_val) else charToRaw(str_val)

  # OpenSSL-compatible EVP_BytesToKey (MD5-based, count=1) — accepts raw pw bytes.
  #   D0 = MD5(pw + salt), D1 = MD5(D0 + pw + salt), D2 = MD5(D1 + pw + salt)
  #   key = D0 || D1  (32 bytes), IV = D2  (16 bytes)
  # Matches rij_salt_and_iv() in lib/cipher_funcs.c
  evp_bytes_to_key <- function(pw_raw, salt) {
    d   <- raw(0)
    out <- raw(0)
    while (length(out) < 48L) {
      d   <- openssl::md5(c(d, pw_raw, salt))
      out <- c(out, d)
    }
    list(key = out[1:32], iv = out[33:48])
  }

  # PKCS#7-pad a raw vector to a multiple of 16 bytes
  pkcs7_pad <- function(data) {
    n <- 16L - (length(data) %% 16L)
    c(data, as.raw(rep(as.integer(n), n)))
  }

  # ── Step 1: assemble plaintext SPA message ─────────────────────────────────────
  #
  # Wire format (colon-separated):
  #   <16-digit-rand>:<username_b64>:<unix_ts>:3.0.0:1:<access_msg_b64>:<sha256_b64>
  #
  # Message type 1 = FKO_ACCESS_MSG  (lib/fko_message.c)
  build_plaintext <- function(access) {
    rand_val  <- paste(sample(0:9, 16, replace = TRUE), collapse = "")
    username  <- b64(charToRaw(Sys.info()[["user"]]))
    timestamp <- as.integer(Sys.time())
    spa_msg   <- b64(charToRaw(access))

    fields <- paste(rand_val, username, timestamp, "3.0.0", 1L, spa_msg, sep = ":")

    # SHA-256 digest of the assembled fields; trailing '=' stripped (fwknop convention)
    sha_b64 <- sub("=+$", "", b64(openssl::sha256(charToRaw(fields))))

    paste0(fields, ":", sha_b64)
  }

  # ── Step 2: AES-256-CBC encryption (OpenSSL "Salted__" wire format) ─────────────
  #
  # Wire: "Salted__" (8 bytes) || random-salt (8 bytes) || PKCS7-padded ciphertext
  # Then base64-encoded — starts with "U2FsdGVkX1" (= base64("Salted__"))
  spa_encrypt <- function(plaintext, key_raw) {
    salt   <- openssl::rand_bytes(8)
    kd     <- evp_bytes_to_key(key_raw, salt)
    padded <- pkcs7_pad(charToRaw(plaintext))

    aes <- digest::AES(kd$key, mode = "CBC", IV = kd$iv)
    ct  <- aes$encrypt(padded)

    sub("=+$", "", b64(c(charToRaw("Salted__"), salt, ct)))
  }

  # ── Step 3: optional HMAC-SHA256 (appended to the encrypted payload) ───────────
  #
  # HMAC is computed over the FULL base64 string including the "U2FsdGVkX1" prefix
  # (matches fko_set_spa_hmac() which operates on ctx->encrypted_msg before the
  # prefix is stripped by fko_get_spa_data()).
  spa_add_hmac <- function(full_b64, hmac_key_raw) {
    # openssl::sha256(x, key=) computes HMAC-SHA256 when key is supplied
    mac     <- openssl::sha256(charToRaw(full_b64), key = hmac_key_raw)
    mac_b64 <- sub("=+$", "", b64(mac))
    paste0(full_b64, mac_b64)
  }

  # Strip the leading "U2FsdGVkX1" (B64_RIJNDAEL_SALT_STR_LEN = 10) before sending.
  # fko_get_spa_data() does: *spa_data += B64_RIJNDAEL_SALT_STR_LEN
  # The server rejects any packet that still starts with this prefix.
  strip_salt_prefix <- function(full_b64) substring(full_b64, 11)

  # ── Step 4: send UDP packet ────────────────────────────────────────────────────
  send_udp <- function(payload, host, port) {
    if (.Platform$OS.type == "windows") {
      # Write a temp PS1 file — avoids inline -Command quoting/length limits
      tmp <<- tempfile(fileext = ".ps1")
      #on.exit(unlink(tmp))
      writeLines(c(
        '$u = New-Object System.Net.Sockets.UdpClient',
        sprintf('$b = [System.Text.Encoding]::ASCII.GetBytes("%s")', payload),
        sprintf('[void]$u.Send($b, $b.Length, "%s", %d)', host, port),
        '$u.Close()'
      ), tmp)
      ret <- system2("powershell",
                     c("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-File", tmp))
      if (ret != 0) warning("powershell exited with code ", ret)
    } else {
      tmp <- tempfile(fileext = ".spa")
      on.exit(unlink(tmp))
      writeBin(charToRaw(payload), tmp)
      rc <- system(sprintf("nc -u -w1 %s %d < %s 2>/dev/null", host, port, tmp),
                   ignore.stdout = TRUE, ignore.stderr = TRUE)
      if (rc != 0)
        system(sprintf("bash -c 'cat %s > /dev/udp/%s/%d'", tmp, host, port))
    }
  }

  # ── Main ───────────────────────────────────────────────────────────────────────
  if (verbose) cat(sprintf("fwknop SPA client (R)\nTarget : %s:%s\nAccess : %s\n\n",
                           SPA_SERVER, SPA_PORT, SPA_ACCESS))

  plaintext <- build_plaintext(SPA_ACCESS)
  if (verbose) cat(sprintf("Plaintext  : %d chars\n  %.72s...\n\n", nchar(plaintext), plaintext))

  enc_key  <- key_raw(SPA_KEY_BASE64, SPA_KEY)
  hmac_key <- if (!is.null(SPA_HMAC_KEY_BASE64) || !is.null(SPA_HMAC_KEY))
    key_raw(SPA_HMAC_KEY_BASE64, SPA_HMAC_KEY) else NULL

  full_b64 <- spa_encrypt(plaintext, enc_key)
  if (verbose) cat(sprintf("Encrypted  : %d chars  (starts with %s...)\n",
                           nchar(full_b64), substr(full_b64, 1, 20)))

  if (!is.null(hmac_key)) {
    full_b64 <- spa_add_hmac(full_b64, hmac_key)
    if (verbose) cat(sprintf("+ HMAC-SHA256 appended → %d chars total\n", nchar(full_b64)))
  }

  # Strip "U2FsdGVkX1" prefix — server rejects packets that include it
  payload <- strip_salt_prefix(full_b64)
  cat(sprintf("\nSending %d-byte SPA packet → UDP %s:%s ...\n",
              nchar(payload), SPA_SERVER, SPA_PORT))
  invisible(suppressWarnings({udpprobe::udp_send_payload(host = SPA_SERVER, port = SPA_PORT, payload = charToRaw(payload), timeout = 0.001, max_response_size = 4)}))
}

