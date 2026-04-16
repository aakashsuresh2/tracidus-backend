/* threat_database.js
   TRACIDUS — Threat-Centric Reality Database (Explained)
*/

window.TRACIDUS_THREATS = {

  credential_phishing: {
    label: "Credential Harvesting Threat",

    user_actions: [
      {
        id: "click_link",
        label: "Clicked a link",
        explain: "You clicked a link that appeared legitimate but originated from an untrusted source."
      }
    ],

    capabilities_granted: [
      {
        label: "Browser navigated to external domain",
        explain: "Your browser loaded a webpage controlled by someone else."
      }
    ],

    mechanisms: [
      {
        label: "Redirect chain executed",
        explain: "The link silently forwarded your browser through multiple servers to hide the final destination."
      },
      {
        label: "Fake login page rendered",
        explain: "A webpage designed to look like a real service login was displayed."
      }
    ],

    internal_transformations: [
      {
        label: "Credential capture script attached",
        explain: "JavaScript code was injected to read whatever you type into the login form."
      },
      {
        label: "Form submission intercepted",
        explain: "Your username and password were copied before being sent anywhere else."
      }
    ],

    external_interactions: [
      {
        label: "Credentials exfiltrated",
        explain: "The stolen credentials were sent to the attacker’s server."
      },
      {
        label: "Credential replay attempted",
        explain: "The attacker tried logging into real services using your credentials."
      }
    ],

    persistence: [
      {
        label: "Password reset suppression",
        explain: "Attackers attempt to prevent or delay you from recovering the account."
      }
    ],

    resulting_reality: [
      {
        label: "Account takeover",
        explain: "Your account is now controlled by someone else."
      }
    ]
  },

  malware_delivery: {
    label: "Malware Delivery Threat",

    user_actions: [
      {
        label: "Downloaded and opened a file",
        explain: "You ran a file obtained from an unverified source."
      }
    ],

    capabilities_granted: [
      {
        label: "Executable loaded into memory",
        explain: "The operating system allowed the file to run as a program."
      }
    ],

    mechanisms: [
      {
        label: "Payload unpacked",
        explain: "Hidden malicious code was extracted from inside the file."
      }
    ],

    internal_transformations: [
      {
        label: "Process spawned",
        explain: "A new background program was started without your awareness."
      },
      {
        label: "Memory injection",
        explain: "Malicious code was injected into another trusted process."
      }
    ],

    external_interactions: [
      {
        label: "Command-and-control beacon",
        explain: "The malware contacted a remote server for instructions."
      }
    ],

    persistence: [
      {
        label: "Startup persistence installed",
        explain: "The malware ensured it runs every time the system starts."
      }
    ],

    resulting_reality: [
      {
        label: "Persistent backdoor",
        explain: "Your system remains accessible to attackers over time."
      }
    ]
  }

};
