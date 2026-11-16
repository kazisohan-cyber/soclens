// False-positive sweep: runs real, legitimate senders and domains through lib/analyzer.js
// and prints every one that is not "safe". No network access.
// node tests/fp-sweep.mjs            (exit code 1 if anything is flagged)
import { createRequire } from 'node:module';
const req = createRequire(import.meta.url);
globalThis.self = globalThis; globalThis.window = globalThis;
req('../extension/lib/public-suffixes.js');
const A = req('../extension/lib/analyzer.js');

// Real notification senders, by the brand their display name claims.
// Sources: each company's own help pages on which addresses it sends from, plus real mail seen in our inboxes.
const SENDERS = {
  Facebook: ['notification@facebookmail.com', 'security@facebookmail.com', 'no-reply@business.metamail.com', 'noreply@meta.com', 'no-reply@mail.instagram.com', 'security@mail.instagram.com', 'noreply@whatsapp.com'],
  Instagram: ['no-reply@mail.instagram.com'],
  WhatsApp: ['noreply@whatsapp.com'],
  Microsoft: ['account-security-noreply@accountprotection.microsoft.com', 'Office365Alerts@microsoft.com', 'msonlineservicesteam@microsoftonline.com',
    'maccount@microsoft.com', 'no-reply@teams.mail.microsoft', 'noreply@email.teams.microsoft.com', 'microsoft@email.microsoft.com',
    'azure-noreply@microsoft.com', 'no-reply@sharepointonline.com', 'microsoft-noreply@microsoft.com', 'noreply@onedrive.com',
    'msa@communication.microsoft.com', 'microsoftstore@microsoftstoreemail.com', 'promotions@email.microsoftemail.com', 'outlook-noreply@outlook.com'],
  'Microsoft Outlook': ['no-reply@microsoft.com'],
  'Microsoft Teams': ['noreply@email.teams.microsoft.com'],
  Google: ['no-reply@accounts.google.com', 'gemini-notes@google.com', 'calendar-notification@google.com', 'payments-noreply@google.com',
    'drive-shares-dm-noreply@google.com', 'workspace-noreply@google.com', 'noreply-workspace-studio@google.com', 'googleplay-noreply@google.com',
    'noreply@youtube.com', 'no-reply@youtube.com', 'mail-noreply@google.com', 'googlecommunityteam-noreply@google.com', 'android-noreply@google.com',
    'sc-noreply@google.com', 'noreply-analytics@google.com', 'ads-account-noreply@google.com', 'forms-receipts-noreply@google.com'],
  Gmail: ['mail-noreply@google.com'],
  YouTube: ['noreply@youtube.com', 'no-reply@youtube.com'],
  Apple: ['no_reply@email.apple.com', 'appleid@id.apple.com', 'noreply@email.apple.com', 'news@insideapple.apple.com', 'do_not_reply@itunes.com',
    'no_reply@icloud.com', 'noreply@apple.com', 'App Store Connect <no_reply@email.apple.com>'.match(/<(.+)>/)[1]],
  iCloud: ['noreply@email.apple.com'],
  Amazon: ['auto-confirm@amazon.com', 'shipment-tracking@amazon.com', 'account-update@amazon.com', 'no-reply@amazon.co.uk', 'order-update@amazon.in',
    'auto-confirm@amazon.de', 'auto-confirm@amazon.sg', 'auto-confirm@amazon.ae', 'auto-confirm@amazon.ca', 'auto-confirm@amazon.fr', 'auto-confirm@amazon.it',
    'auto-confirm@amazon.es', 'auto-confirm@amazon.co.jp', 'auto-confirm@amazon.com.au', 'auto-confirm@amazon.nl', 'auto-confirm@amazon.sa', 'auto-confirm@amazon.pl',
    'auto-confirm@amazon.se', 'auto-confirm@amazon.eg', 'auto-confirm@amazon.com.tr', 'store-news@amazon.com', 'digital-no-reply@amazon.com', 'primevideo@primevideo.com'],
  'Amazon Web Services': ['aws-marketing-email-replies@amazon.com', 'no-reply@signin.aws', 'aws-verification@verify.signin.aws', 'no-reply-aws@amazon.com', 'aws-billing@amazon.com', 'noreply@aws.amazon.com'],
  AWS: ['no-reply-aws@amazon.com', 'no-reply@signin.aws'],
  PayPal: ['service@paypal.com', 'service@intl.paypal.com', 'paypal@mail.paypal.com', 'service@paypal.co.uk', 'service@paypal.de', 'service@paypal.com.au',
    'paypal@emails.paypal.com', 'service@paypal.fr', 'service@paypal.it', 'service@paypal.es', 'service@paypal.ca', 'service@paypal.in'],
  DocuSign: ['dse@docusign.net', 'dse_na2@docusign.net', 'dse_na3@docusign.net', 'dse@eumail.docusign.net', 'dse@camail.docusign.net', 'noreply@docusign.com'],
  Dropbox: ['no-reply@dropbox.com', 'no-reply@dropboxmail.com', 'no-reply@em.dropbox.com'],
  'Dropbox Sign': ['noreply@mail.hellosign.com', 'noreply@hellosign.com'],
  Adobe: ['message@adobe.com', 'mail@mail.adobe.com', 'echosign@echosign.com', 'adobesign@adobesign.com', 'noreply@adobesign.com', 'noreply@email.adobe.com', 'no-reply@acrobat.com'],
  'Adobe Acrobat Sign': ['echosign@echosign.com', 'adobesign@adobesign.com'],
  DHL: ['noreply@dhl.com', 'no-reply@dhl.de', 'noreply@dhl.co.uk', 'noreply@dhlparcel.nl', 'noreply@dhl.com.my', 'noreply@dhl.com.sg', 'noreply@dpdhl.com'],
  'DHL Express': ['noreply@dhl.com'],
  FedEx: ['trackingupdates@fedex.com', 'noreply@fedex.com', 'tracking@notify.fedex.com'],
  LinkedIn: ['messages-noreply@linkedin.com', 'security-noreply@linkedin.com', 'invitations@linkedin.com', 'jobs-noreply@linkedin.com', 'updates-noreply@linkedin.com',
    'news@e.linkedin.com', 'linkedin@e.linkedin.com', 'jobalerts-noreply@linkedin.com', 'notifications-noreply@linkedin.com'],
  Netflix: ['info@account.netflix.com', 'info@mailer.netflix.com', 'info@members.netflix.com', 'info@netflix.com'],
  Okta: ['noreply@okta.com', 'noreply@okta-emea.com'],
  Zoom: ['no-reply@zoom.us', 'serena.wong@zoom.us', 'noreply@zoom.com', 'no-reply@zoomgov.com'],
  Wise: ['noreply@wise.com', 'noreply@info.wise.com'],
  Maybank: ['noreply@maybank.com', 'noreply@maybank2u.com.my', 'alerts@maybank.com.sg'],
  CIMB: ['noreply@cimb.com', 'cimbclicks@cimb.com', 'noreply@cimbclicks.com.my'],
  DBS: ['ibanking.alert@dbs.com', 'noreply@dbs.com.sg'],
  OCBC: ['notifications@ocbc.com', 'noreply@ocbc.com.my'],
  UOB: ['unialerts@uobgroup.com', 'noreply@uob.com.my'],
  bKash: ['noreply@bkash.com'],
  Binance: ['do-not-reply@binance.com', 'do-not-reply@post.binance.com', 'do_not_reply@mailer.binance.com', 'do-not-reply@ses.binance.com'],
  Coinbase: ['no-reply@coinbase.com', 'no-reply@info.coinbase.com', 'no-reply@mail.coinbase.com'],
  Steam: ['noreply@steampowered.com'],
  'Steam Support': ['noreply@steampowered.com']
};

// Legitimate sites whose name happens to contain a brand word. None of these should be blocked or warned.
const DOMAINS = [
  'metallica.com', 'metacritic.com', 'metamask.io', 'metabase.com', 'metalinjection.net', 'wiseman.com', 'otherwise.com', 'wisesoft.com',
  'dbschenker.com', 'uobkayhian.com', 'applebees.com', 'pineapple.com', 'appleinsider.com', 'zoominfo.com', 'zoomcar.com', 'dhlparcel.nl',
  'steamboat.com', 'steamunlocked.net', 'oktapost.com', 'netflixtechblog.com', 'amazonpay.in', 'googleblog.com', 'blog.google', 'outlookindia.com',
  'microsoftpressstore.com', 'paypal-community.com', 'linkedinlearning.com', 'dropboxforum.com', 'adobeexchange.com', 'docusign.co.uk', 'fedexcup.com',
  'cimbbank.com.sg', 'maybankard.com', 'binance.info', 'coinbasecloud.net', 'instagramtips.com', 'facebookbrand.com',
  'workplace.com', 'oculus.com', 'threads.net', 'icloud.com.cn', 'apple.co', 'amazon.jobs', 'aboutamazon.com', 'awsevents.com', 'wiz.io',
  'outlook.live.com', 'office.com', 'microsoftstream.com', 'msft.it', 'yammer.com', 'ebay.com', 'bkashcluster.com'
];

const subject = 'Your account: please review';
const flagged = [];
let n = 0;
for (const [name, list] of Object.entries(SENDERS)) {
  for (const addr of list) {
    n++;
    const r = A.analyzeEmail({ senderName: name, senderEmail: addr, subject, text: 'Notification from your account.', links: [], attachments: [] });
    if (r.level !== 'safe') flagged.push(['email', `${name} <${addr}>`, r.level, r.score, r.reasons.join('; ')]);
  }
}
for (const d of DOMAINS) {
  n++;
  const v = A.analyzeUrl('https://' + d + '/');
  if (v.level !== 'safe') flagged.push(['url', d, v.level, v.score, v.reasons.join('; ')]);
}
console.log(`checked ${n}, flagged ${flagged.length}`);
for (const f of flagged) console.log(f.join(' | '));
process.exitCode = flagged.length ? 1 : 0;
