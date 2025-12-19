rule PrivateKey {
    meta:
        description = "Detects private keys (RSA, DSA, EC, OpenSSH)"
        severity = "HIGH"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $pkcs8 = "-----BEGIN PRIVATE KEY-----"
    condition:
        any of them
}

rule APIToken {
    meta:
        description = "Detects API tokens in various formats"
        severity = "HIGH"
    strings:
        $api_key1 = /api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9_-]{20,}['"]?/ nocase
        $api_key2 = /apikey\s*[:=]\s*['"]?[A-Za-z0-9_-]{20,}['"]?/ nocase
        $token = /token\s*[:=]\s*['"]?[A-Za-z0-9_-]{20,}['"]?/ nocase
    condition:
        any of them
}

rule HardcodedCredentials {
    meta:
        description = "Detects hardcoded username/password combinations"
        severity = "HIGH"
    strings:
        $password1 = /password\s*[:=]\s*[a-zA-Z0-9_+\/=!@#$%]{8,}/ nocase
        $password2 = /PASSWORD\s*=\s*[a-zA-Z0-9_+\/=!@#$%]{8,}/
        $pwd = /pwd\s*[:=]\s*[a-zA-Z0-9_+\/=!@#$%]{8,}/ nocase
    condition:
        any of them
}

rule DatabaseCredentials {
    meta:
        description = "Detects database connection strings with credentials"
        severity = "HIGH"
    strings:
        $mysql = "mysql://" nocase
        $postgres = "postgresql://" nocase
        $mongodb = "mongodb://" nocase
        $redis = "redis://" nocase
    condition:
        any of them
}

rule Certificate {
    meta:
        description = "Detects SSL/TLS certificates"
        severity = "MEDIUM"
    strings:
        $cert = "-----BEGIN CERTIFICATE-----"
        $cert_chain = "-----BEGIN CERTIFICATE REQUEST-----"
    condition:
        any of them
}

rule SensitiveConfig {
    meta:
        description = "Detects sensitive configuration patterns"
        severity = "MEDIUM"
    strings:
        $secret = /secret\s*[:=]\s*[a-zA-Z0-9_+\/=]{10,}/ nocase
        $private_key = /private_key\s*[:=]\s*[a-zA-Z0-9_+\/=]{10,}/ nocase
        $secret_key = /secret_key\s*[:=]\s*[a-zA-Z0-9_+\/=]{10,}/ nocase
    condition:
        any of them
}

rule InternalEndpoint {
    meta:
        description = "Detects internal/private IP addresses"
        severity = "LOW"
    strings:
        $localhost = /localhost[:\/]/ nocase
        $private_ip1 = /127\.0\.0\.1[:\/]/
        $private_ip2 = /192\.168\.\d+\.\d+[:\/]/
        $private_ip3 = /10\.\d+\.\d+\.\d+[:\/]/
    condition:
        any of them
}

rule FirebaseConfig {
    meta:
        description = "Detects Firebase configuration and API keys"
        severity = "HIGH"
    strings:
        $firebase_key = "AIza" nocase
        $firebase_url = "firebaseio.com" nocase
        $firebase_api = "firebase" nocase
    condition:
        any of them
}

rule AWSMobileCredentials {
    meta:
        description = "Detects AWS Mobile/Amplify credentials"
        severity = "HIGH"
    strings:
        $aws_access = "AKIA"
        $aws_secret = "aws_secret_access_key" nocase
        $amplify = "amplify" nocase
    condition:
        any of them
}

rule AndroidKeystorePassword {
    meta:
        description = "Detects Android keystore passwords"
        severity = "HIGH"
    strings:
        $keystore = "keystore" nocase
        $store_pass = "storePassword" nocase
        $key_pass = "keyPassword" nocase
    condition:
        any of them
}

rule SmaliHardcodedString {
    meta:
        description = "Detects hardcoded strings in smali bytecode"
        severity = "MEDIUM"
    strings:
        $const_string = "const-string"
        $api_pattern = /const-string.+api[_-]?key/
        $password_pattern = /const-string.+password/
        $token_pattern = /const-string.+token/
    condition:
        $const_string and (any of ($api_pattern, $password_pattern, $token_pattern))
}

rule MobileAPIKeys {
    meta:
        description = "Detects common mobile SDK API keys"
        severity = "HIGH"
    strings:
        $facebook = "EAACEdEose0cBA"
        $google = "AIza" nocase
        $stripe_test = "sk_test_"
        $stripe_live = "sk_live_"
        $twilio = "SK" nocase
        $sendgrid = "SG."
    condition:
        any of them
}

rule PaymentGatewayKeys {
    meta:
        description = "Detects payment gateway API keys and secrets"
        severity = "HIGH"
    strings:
        $stripe_secret = "sk_test_" nocase
        $stripe_live = "sk_live_" nocase
        $stripe_pub = "pk_test_" nocase
        $paypal = "access_token" nocase
        $square_access = "sq0atp-"
        $square_secret = "sq0csp-"
    condition:
        any of them
}

rule PushNotificationKeys {
    meta:
        description = "Detects push notification service keys"
        severity = "MEDIUM"
    strings:
        $fcm = "fcm" nocase
        $onesignal = "onesignal" nocase
        $apns = "apns" nocase
        $server_key = "server_key" nocase
    condition:
        2 of them
}

rule AnalyticsKeys {
    meta:
        description = "Detects analytics and tracking SDK keys"
        severity = "LOW"
    strings:
        $mixpanel = "mixpanel" nocase
        $amplitude = "amplitude" nocase
        $segment = "segment" nocase
        $crashlytics = "crashlytics" nocase
    condition:
        any of them
}

rule AndroidManifestSecrets {
    meta:
        description = "Detects secrets in AndroidManifest.xml"
        severity = "HIGH"
    strings:
        $manifest = "AndroidManifest"
        $meta_data = "meta-data"
        $api_key = "android:value" nocase
    condition:
        $manifest and $meta_data and $api_key
}

rule iOSInfoPlistSecrets {
    meta:
        description = "Detects secrets in iOS Info.plist"
        severity = "HIGH"
    strings:
        $plist = "plist"
        $key = "<key>"
        $string = "<string>"
        $api = "API" nocase
    condition:
        $plist and $key and $string and $api
}


