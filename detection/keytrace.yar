/*
 * keytrace.yar — Detection rule for KeyTrace artifacts and binaries.
 *
 * Author : KeyTrace Educational Project
 * Purpose: Demonstrate detection-engineering thinking for a tool that the
 *          same author built. Two rules:
 *            1. KeyTrace_EncryptedLog  — finds .kt.enc files on disk
 *            2. KeyTrace_PythonRunner  — finds the source/installed package
 *
 * Tested against: keytrace v0.1.0
 */

rule KeyTrace_EncryptedLog
{
    meta:
        description = "Encrypted session log produced by KeyTrace"
        author      = "KeyTrace Educational Project"
        reference   = "https://github.com/<you>/keytrace"
        severity    = "medium"
        mitre_attack = "T1056.001"   // Input Capture: Keylogging

    strings:
        $magic = { 4B 54 52 43 }                  // "KTRC"
        $ver   = { 01 }                           // current format version

    condition:
        // Magic at offset 0, version byte immediately after, file >= header size
        $magic at 0 and $ver at 4 and filesize >= 33
}


rule KeyTrace_PythonRunner
{
    meta:
        description = "KeyTrace Python source artifacts (package files)"
        author      = "KeyTrace Educational Project"
        severity    = "high"
        mitre_attack = "T1056.001"

    strings:
        $s1 = "KeyTrace — Keystroke Telemetry" ascii
        $s2 = "from pynput import keyboard" ascii
        $s3 = "AESGCM(key)" ascii
        $s4 = "CONSENT.md" ascii
        $s5 = "keytrace-genesis-v1" ascii

    condition:
        3 of them
}


rule KeyTrace_PassphraseEnvVar
{
    meta:
        description = "Process environment containing KEYTRACE_PASS"
        author      = "KeyTrace Educational Project"
        severity    = "informational"
        comment     = "Run against /proc/<pid>/environ on Linux during IR"

    strings:
        $e = "KEYTRACE_PASS=" ascii

    condition:
        $e
}
