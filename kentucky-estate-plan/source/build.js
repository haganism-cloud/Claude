const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, Footer, PageNumber,
  LevelFormat, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
} = require('docx');

const OUT = process.argv[2];
fs.mkdirSync(OUT, { recursive: true });

const FONT = 'Times New Roman';
const BLANK = '______________________________';

// Inline markup: **bold**, [FILL-IN] highlighted yellow so reviewers can find every blank.
function runs(text, base = {}) {
  return text.split(/(\*\*[^*]+\*\*|\[[^\]]+\])/).filter(Boolean).map((t) => {
    if (t.startsWith('**')) return new TextRun({ text: t.slice(2, -2), bold: true, ...base });
    if (t.startsWith('[')) return new TextRun({ text: t, highlight: 'yellow', ...base });
    return new TextRun({ text: t, ...base });
  });
}

const P = (text, opts = {}) => new Paragraph({
  children: runs(text, opts.run),
  alignment: opts.align ?? AlignmentType.JUSTIFIED,
  spacing: { after: opts.after ?? 160, line: 276 },
  indent: opts.indent,
  keepNext: opts.keepNext,
});

function render(items) {
  const out = [];
  for (const it of items) {
    if (it.title) {
      out.push(new Paragraph({ children: runs(it.title, { bold: true, size: 32 }), alignment: AlignmentType.CENTER, spacing: { after: 120 } }));
    } else if (it.subtitle) {
      out.push(new Paragraph({ children: runs(it.subtitle, { italics: true }), alignment: AlignmentType.CENTER, spacing: { after: 360 } }));
    } else if (it.h) {
      out.push(new Paragraph({ children: runs(it.h, { bold: true, size: 26 }), alignment: AlignmentType.LEFT, spacing: { before: 240, after: 120 }, keepNext: true }));
    } else if (it.art) {
      out.push(new Paragraph({ children: runs(it.art, { bold: true }), alignment: AlignmentType.LEFT, spacing: { before: 200, after: 80 }, keepNext: true }));
      for (const t of [].concat(it.text)) if (t) out.push(P(t));
    } else if (it.p) {
      out.push(P(it.p, it));
    } else if (it.center) {
      out.push(P(it.center, { align: AlignmentType.CENTER, after: 60 }));
    } else if (it.left) {
      out.push(P(it.left, { align: AlignmentType.LEFT, after: 60 }));
    } else if (it.bullets) {
      for (const b of it.bullets) out.push(new Paragraph({ children: runs(b), numbering: { reference: 'bullets', level: 0 }, spacing: { after: 80 }, alignment: AlignmentType.LEFT }));
    } else if (it.checks) {
      for (const c of it.checks) out.push(P('_____ ' + c, { align: AlignmentType.LEFT, indent: { left: 720, hanging: 720 }, after: 120 }));
    } else if (it.boxes) {
      for (const c of it.boxes) out.push(P('☐  ' + c, { align: AlignmentType.LEFT, indent: { left: 360, hanging: 360 }, after: 100 }));
    } else if (it.sig) {
      out.push(new Paragraph({ children: [new TextRun('')], spacing: { before: 360, after: 0 }, keepNext: true }));
      out.push(new Paragraph({ children: [new TextRun(BLANK + '______')], spacing: { after: 0 }, keepNext: true }));
      for (const [i, line] of [].concat(it.sig).entries()) {
        out.push(new Paragraph({ children: runs(line), spacing: { after: 0 }, keepNext: i < [].concat(it.sig).length - 1 }));
      }
    } else if (it.table) {
      out.push(table(it.table, it.widths));
      out.push(P('', { after: 120 }));
    } else if (it.pb) {
      out.push(new Paragraph({ children: [], pageBreakBefore: true }));
    }
  }
  return out;
}

function table(rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const border = { style: BorderStyle.SINGLE, size: 4, color: '808080' };
  const borders = { top: border, bottom: border, left: border, right: border };
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    rows: rows.map((r, ri) => new TableRow({
      tableHeader: ri === 0,
      cantSplit: true,
      children: r.map((c, ci) => new TableCell({
        width: { size: widths[ci], type: WidthType.DXA },
        borders,
        shading: ri === 0 ? { type: ShadingType.CLEAR, color: 'auto', fill: 'E7E6E6' } : undefined,
        margins: { top: 60, bottom: 60, left: 100, right: 100 },
        children: [new Paragraph({ children: runs(c, ri === 0 ? { bold: true } : {}), spacing: { after: 0 } })],
      })),
    })),
  });
}

function build(file, items, footerLabel) {
  const doc = new Document({
    creator: 'Draft for attorney review',
    styles: { default: { document: { run: { font: FONT, size: 24 } } } },
    numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }] },
    sections: [{
      properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: footerLabel ? footerLabel + '          ' : '', size: 18 }),
              new TextRun({ children: ['Page ', PageNumber.CURRENT, ' of ', PageNumber.TOTAL_PAGES], size: 18 }),
            ],
          })],
        }),
      },
      children: render(items),
    }],
  });
  return Packer.toBuffer(doc).then((buf) => fs.writeFileSync(path.join(OUT, file), buf));
}

const notary = (who, what) => [
  { left: 'COMMONWEALTH OF KENTUCKY' },
  { left: 'COUNTY OF [COUNTY]' },
  { p: `${what} was acknowledged before me on [DATE] by ${who}.` },
  { sig: ['Notary Public, Kentucky State at Large', 'Notary ID No.: [NUMBER]', 'My commission expires: [DATE]          (Seal)'] },
];

// ---------------------------------------------------------------- 00 Checklist
const checklist = [
  { title: 'Kentucky Estate Planning Documents' },
  { subtitle: 'Review notes and signing checklist (single person, no children). Draft prepared [DATE].' },
  { p: '**These are drafts for review by a Kentucky-licensed attorney, not legal advice.** Every item highlighted in yellow is a blank to complete or a choice to make. Statute citations should be checked against the current Kentucky Revised Statutes before signing.' },
  { h: 'Documents in this set' },
  { table: [
    ['Document', 'Governing law', 'How it must be signed', 'Filed or recorded?'],
    ['01 Last Will and Testament', 'KRS Chapter 394', 'Testator plus 2 adult witnesses, all present together. Notary only for the self-proving affidavit.', 'Not filed while living. Probated in District Court after death. Keep the original safe.'],
    ['02 Living Will Directive and Health Care Surrogate', 'KRS 311.621 to 311.643', 'Grantor plus 2 qualified adult witnesses, OR before a notary.', 'Not filed. Give copies to surrogates, doctors and hospital.'],
    ['03 Durable Power of Attorney (financial)', 'KRS Chapter 457', 'Principal signs before a notary; 2 witnesses recommended.', 'Record with the County Clerk only if the agent will deal with real estate.'],
    ['04 Irrevocable Trust Agreement', 'KRS Chapter 386B', 'Settlor and trustee sign before a notary.', 'Not filed. Fund it by deed (recorded) and retitling accounts. Trust needs its own EIN.'],
  ], widths: [2300, 1700, 2900, 2460] },
  { h: 'Signing day checklist' },
  { bullets: [
    'Bring government photo ID for the person signing and for each witness.',
    'Arrange 2 adult witnesses who are **not** named in any document, are not related to you, and are not your health care providers or employees of your health care facility.',
    'Arrange a Kentucky notary (needed for the will affidavit, the power of attorney and the trust; optional for the living will if 2 witnesses sign).',
    'Initial the bottom of every page of the will, and every choice you select in the living will and power of attorney.',
    'Sign in blue ink. Do not unstaple or remove pages from the will after signing.',
    'Store originals in a fireproof place or with your attorney. Tell your executor and agents where they are.',
  ] },
  { h: 'Points for the reviewing attorney' },
  { bullets: [
    'Will: confirm residuary beneficiaries and whether a charity is intended. Confirm coordination with the irrevocable trust (pour-over not included because the trust is irrevocable).',
    'Living will: drafted from the statutory form in KRS 311.625. Confirm the current form text and organ donation cross-references.',
    'Power of attorney: confirm current execution requirements in KRS 457.050 and which special powers under KRS 457.220 should be granted.',
    'Trust: confirm grantor vs. non-grantor tax status, gift tax reporting (Form 709), Medicaid 60-month look-back exposure, and deed preparation for any real estate (KRS 382.335 preparer statement).',
    'Beneficiary designations (life insurance, retirement accounts, POD/TOD accounts) pass outside the will and should be updated to match the plan.',
  ] },
];

// ---------------------------------------------------------------- 01 Will
const will = [
  { title: 'LAST WILL AND TESTAMENT' },
  { title: 'OF' },
  { title: '[FULL LEGAL NAME]' },
  { subtitle: '' },
  { p: 'I, [FULL LEGAL NAME], a resident of [CITY], [COUNTY] County, Kentucky, being of sound mind and at least eighteen (18) years of age, and acting freely and without undue influence, declare this to be my Last Will and Testament.' },
  { art: 'ARTICLE I. REVOCATION OF PRIOR WILLS', text: 'I revoke all wills and codicils previously made by me.' },
  { art: 'ARTICLE II. FAMILY STATUS', text: 'I am not married, and I have no children, living or deceased, natural or adopted. I have intentionally made no provision in this Will for any person claiming to be my child or descendant, except as expressly stated in this Will. [My parents are NAMES. My siblings are NAMES.]' },
  { art: 'ARTICLE III. PAYMENT OF DEBTS, EXPENSES AND TAXES', text: 'I direct my Executor to pay from the residue of my estate my legally enforceable debts, the expenses of my last illness and funeral, and the expenses of administering my estate. My Executor need not prepay any debt secured by a mortgage, lien or pledge. All estate, inheritance and similar taxes payable by reason of my death on property passing under this Will shall be paid from the residue of my estate without apportionment.' },
  { art: 'ARTICLE IV. TANGIBLE PERSONAL PROPERTY', text: [
    'I give all my tangible personal property, including household furnishings, jewelry, clothing, books, personal effects and automobiles, together with any insurance on that property, to [NAME, RELATIONSHIP], if that person survives me. If that person does not survive me, I give this property to the beneficiaries of my residuary estate under Article VI, to be divided among them as they agree, or, if they do not agree within ninety (90) days after my Executor qualifies, as my Executor decides in my Executor’s sole discretion.',
    'I may leave a signed memorandum expressing my wishes about specific items. I request, but do not require, that my Executor and beneficiaries honor it.',
  ] },
  { art: 'ARTICLE V. SPECIFIC GIFTS', text: [
    '[OPTIONAL. Delete this Article if not used.] I make the following gifts, each conditioned on the beneficiary surviving me:',
    '(a) To [NAME], the sum of [AMOUNT] Dollars ($[AMOUNT]).',
    '(b) To [CHARITY NAME], a charitable organization located at [ADDRESS], federal EIN [NUMBER], the sum of [AMOUNT] Dollars ($[AMOUNT]), for its general purposes. If it does not then exist or qualify as a charitable organization, my Executor shall give this gift to a similar organization my Executor selects.',
    '(c) To [NAME], my real property located at [ADDRESS], subject to any mortgage on it.',
    'If a beneficiary of a specific gift does not survive me, that gift lapses and becomes part of my residuary estate.',
  ] },
  { art: 'ARTICLE VI. RESIDUARY ESTATE', text: [
    'I give all the rest, residue and remainder of my property of every kind and wherever located, including lapsed gifts (my “residuary estate”), as follows: [NAME, RELATIONSHIP] – [__]%; [NAME, RELATIONSHIP] – [__]%.',
    'If any residuary beneficiary does not survive me, that beneficiary’s share shall pass to that beneficiary’s descendants who survive me, per stirpes, or if none, shall be added proportionately to the shares of the other residuary beneficiaries.',
  ] },
  { art: 'ARTICLE VII. ULTIMATE DISPOSITION', text: 'If no beneficiary named in Article VI or their descendants survive me, I give my residuary estate to [ALTERNATE BENEFICIARY OR CHARITY], or if none, to my heirs at law, determined under the laws of Kentucky then in effect as though I had died unmarried and intestate.' },
  { art: 'ARTICLE VIII. SURVIVORSHIP', text: 'A beneficiary who does not survive me by thirty (30) days shall be treated as having predeceased me.' },
  { art: 'ARTICLE IX. BENEFICIARIES UNDER AGE OR INCAPACITATED', text: 'If any property becomes distributable outright to a person under the age of [25] or who in my Executor’s judgment is incapacitated, my Executor may distribute it to a custodian for that person under the Kentucky Uniform Transfers to Minors Act (KRS Chapter 385), to that person’s guardian or conservator, or may hold it in a separate trust for that person, with [NAME] as trustee, using income and principal for the person’s health, education, maintenance and support, and distributing the balance when the person reaches that age or regains capacity, or to the person’s estate on death.' },
  { art: 'ARTICLE X. EXECUTOR', text: [
    'I appoint [NAME], of [CITY, STATE], as Executor of this Will. If [NAME] fails to qualify or ceases to serve, I appoint [ALTERNATE NAME], of [CITY, STATE], as successor Executor. The term “Executor” includes any personal representative serving under this Will.',
    'No Executor shall be required to give bond or surety in any jurisdiction. If the law requires bond notwithstanding this direction, I request that the minimum bond be set. To the extent permitted by KRS 395.195 and other Kentucky law, my Executor may administer my estate without court supervision.',
  ] },
  { art: 'ARTICLE XI. POWERS OF EXECUTOR', text: 'In addition to all powers granted by Kentucky law, including KRS 395.195, my Executor may, without court order: sell at public or private sale, lease, mortgage or exchange any real or personal property; retain or invest assets as a prudent investor; settle, compromise or abandon claims; continue or wind up any business interest; employ and pay attorneys, accountants and other agents; make tax elections; distribute property in cash or in kind, including in non-pro-rata shares; and access, manage, copy and close my digital assets and electronic accounts and communications to the extent permitted by KRS Chapter 369 (Kentucky Uniform Fiduciary Access to Digital Assets Act).' },
  { art: 'ARTICLE XII. PETS', text: '[OPTIONAL.] I give any pets I own at my death to [NAME], if willing to care for them, together with [AMOUNT] Dollars ($[AMOUNT]) to be used for their care, without any accounting.' },
  { art: 'ARTICLE XIII. FUNERAL AND DISPOSITION OF REMAINS', text: '[OPTIONAL.] I request [burial at LOCATION / cremation]. These wishes are not binding on my Executor. Kentucky law lets me designate a person to control disposition of my remains by a separate written designation (KRS 367.93117); I [have / have not] made such a designation.' },
  { art: 'ARTICLE XIV. GENERAL PROVISIONS', text: 'This Will shall be construed under the laws of the Commonwealth of Kentucky. If any provision is invalid or unenforceable, the remaining provisions shall continue in full effect. Headings are for convenience only. Words of any gender include all genders, and the singular includes the plural where the context requires.' },
  { p: 'IN WITNESS WHEREOF, I have signed this Will, consisting of [NUMBER] pages including the attestation and self-proving affidavit pages, and have initialed each page, on [DATE], at [CITY], Kentucky.', keepNext: true },
  { sig: ['[FULL LEGAL NAME], Testator'] },
  { h: 'ATTESTATION OF WITNESSES' },
  { p: 'On the date last written above, [FULL LEGAL NAME], the Testator, declared to us, the undersigned, that this instrument was the Testator’s Will and requested us to act as witnesses to it. The Testator then signed this Will in our presence, all of us being present at the same time. We now, at the Testator’s request, in the Testator’s presence and in the presence of each other, sign our names as witnesses. Each of us is at least eighteen (18) years of age, is not a beneficiary under this Will, and believes the Testator to be of sound mind and under no constraint or undue influence.', keepNext: true },
  { sig: ['Witness 1 signature', 'Printed name: [NAME]', 'Address: [ADDRESS]'] },
  { sig: ['Witness 2 signature', 'Printed name: [NAME]', 'Address: [ADDRESS]'] },
  { pb: true },
  { title: 'SELF-PROVING AFFIDAVIT' },
  { subtitle: '(KRS 394.225)' },
  { left: 'COMMONWEALTH OF KENTUCKY' },
  { left: 'COUNTY OF [COUNTY]' },
  { p: 'Before me, the undersigned authority, on this day personally appeared [TESTATOR], [WITNESS 1] and [WITNESS 2], known to me to be the Testator and the witnesses, respectively, whose names are signed to the attached or foregoing instrument, and all of these persons being by me first duly sworn, the Testator declared to me and to the witnesses in my presence that the instrument is the Testator’s last will and testament, and that the Testator had willingly signed or directed another to sign it for the Testator, and executed it in the presence of the witnesses as the Testator’s free and voluntary act for the purposes therein expressed; and each of the witnesses stated to me, in the presence and hearing of the Testator, that the Testator signed the will in their presence, that the Testator declared the instrument to be the Testator’s will, that they signed it as witnesses in the presence of the Testator and of each other, and that the Testator, at the time of signing, appeared to be eighteen (18) years of age or over and of sound mind and memory.' },
  { sig: ['[TESTATOR], Testator'] },
  { sig: ['[WITNESS 1], Witness'] },
  { sig: ['[WITNESS 2], Witness'] },
  { p: 'Subscribed, sworn to and acknowledged before me by [TESTATOR], the Testator, and subscribed and sworn to before me by [WITNESS 1] and [WITNESS 2], witnesses, on [DATE].', keepNext: true },
  { sig: ['Notary Public, Kentucky State at Large', 'Notary ID No.: [NUMBER]', 'My commission expires: [DATE]          (Seal)'] },
];

// ---------------------------------------------------------------- 02 Living will / surrogate
const livingWill = [
  { title: 'LIVING WILL DIRECTIVE' },
  { title: 'AND HEALTH CARE SURROGATE DESIGNATION' },
  { subtitle: 'Commonwealth of Kentucky – based on the form in KRS 311.625' },
  { p: 'My wishes regarding life-prolonging treatment and artificially provided nutrition and hydration to be provided to me if I no longer have decisional capacity, have a terminal condition, or become permanently unconscious have been indicated by checking and initialing the appropriate lines below. By checking and initialing the appropriate lines, I specifically:' },
  { checks: [
    'Designate [SURROGATE NAME], of [ADDRESS, PHONE], as my health care surrogate to make health care decisions for me in accordance with this directive when I no longer have decisional capacity. If [SURROGATE NAME] refuses or is not able to act for me, I designate [ALTERNATE SURROGATE NAME], of [ADDRESS, PHONE], as my health care surrogate. Any prior designation is revoked.',
  ] },
  { p: 'If I do not designate a surrogate, the following are my directions to my attending physician. If I have designated a surrogate, my surrogate shall comply with my wishes as indicated below:' },
  { checks: [
    'Withhold or withdraw treatment that serves only to prolong the process of dying, if I have a terminal condition or become permanently unconscious.',
    'Authorize the giving of all treatment, including life-prolonging treatment, unless or until it is medically futile.',
    'Withhold or withdraw artificially provided food, water, or other artificially provided nourishment or fluids, if I have a terminal condition or become permanently unconscious.',
    'Authorize the giving of artificially provided food, water, or other artificially provided nourishment or fluids.',
    'Authorize my surrogate, designated above, to withhold or withdraw artificially provided nourishment or fluids, or other treatment if the surrogate determines that withholding or withdrawing is in my best interest; but I do not mandate that withholding or withdrawing.',
  ] },
  { h: 'Authorization for organ donation' },
  { checks: [
    'I authorize the giving of all or any part of my body upon death for any purpose specified under Kentucky law (KRS 311.1911 to 311.1959).',
    'I do not authorize the giving of all or any part of my body upon death.',
  ] },
  { h: 'Additional instructions (optional)' },
  { p: '[Any specific wishes, e.g., pain relief, religious preferences, hospice, place of care. Delete if none.]' },
  { p: 'In the absence of my ability to give directions regarding the use of life-prolonging treatment and artificially provided nutrition and hydration, it is my intention that this directive shall be honored by my attending physician, my family, and any surrogate designated pursuant to this directive as the final expression of my legal right to refuse medical or surgical treatment and I accept the consequences of the refusal.' },
  { p: 'If I have been diagnosed as pregnant and that diagnosis is known to my attending physician, this directive shall have no force or effect during the course of my pregnancy.' },
  { p: 'I understand the full import of this directive and I am emotionally and mentally competent to make this directive.' },
  { p: 'Signed this [DAY] day of [MONTH], [YEAR].', keepNext: true },
  { sig: ['Signature of Grantor: [FULL LEGAL NAME]', 'Address: [ADDRESS]', 'Date of birth: [DATE]'] },
  { h: 'Execution – complete EITHER the witness section OR the notary section' },
  { p: '**Witnesses.** In our joint presence, the grantor, who is of sound mind and eighteen (18) years of age, or older, voluntarily dated and signed this writing or directed it to be dated and signed for the grantor.', keepNext: true },
  { sig: ['Signature of Witness 1', 'Printed name: [NAME]', 'Address: [ADDRESS]'] },
  { sig: ['Signature of Witness 2', 'Printed name: [NAME]', 'Address: [ADDRESS]'] },
  { p: 'Witnesses may not be: a blood relative of the grantor; a beneficiary of the grantor’s estate; an employee of a health care facility in which the grantor is a patient (unless the employee is a notary); the grantor’s attending physician; or a person directly financially responsible for the grantor’s health care (KRS 311.625).', run: { italics: true, size: 20 } },
  { p: '**OR Notary.**', keepNext: true },
  { left: 'COMMONWEALTH OF KENTUCKY' },
  { left: 'COUNTY OF [COUNTY]' },
  { p: 'Before me, the undersigned authority, came the grantor, [FULL LEGAL NAME], who is of sound mind and eighteen (18) years of age, or older, and acknowledged that the grantor voluntarily dated and signed this writing or directed it to be signed and dated as above. Done this [DAY] day of [MONTH], [YEAR].', keepNext: true },
  { sig: ['Notary Public, Kentucky State at Large', 'Notary ID No.: [NUMBER]', 'My commission expires: [DATE]          (Seal)'] },
  { pb: true },
  { title: 'HIPAA AUTHORIZATION' },
  { subtitle: 'Optional companion release for health care surrogates' },
  { p: 'I, [FULL LEGAL NAME], date of birth [DATE], authorize any health care provider, health plan, or other covered entity under the Health Insurance Portability and Accountability Act of 1996 (45 CFR Parts 160 and 164) to disclose my individually identifiable health information, including information about mental health, substance use and HIV status, to my health care surrogates named in my Living Will Directive: [SURROGATE NAME] and [ALTERNATE SURROGATE NAME].' },
  { p: 'This authorization is effective immediately, so that my surrogates may obtain information needed to determine my capacity and to act for me, and it expires two (2) years after my death unless I revoke it earlier in writing delivered to the provider. Information disclosed under this authorization may be redisclosed and no longer protected by federal privacy rules. My treatment, payment, enrollment or eligibility for benefits may not be conditioned on signing this authorization.' },
  { sig: ['[FULL LEGAL NAME]', 'Date: [DATE]'] },
  { h: 'Distribution' },
  { bullets: [
    'Keep the original with your important papers. Give signed copies to each surrogate, your primary doctor, and any hospital where you receive care.',
    'You may revoke this directive at any time by a signed and dated writing, by destroying it, or by an oral statement to a health care provider (KRS 311.627).',
  ] },
];

// ---------------------------------------------------------------- 03 Financial POA
const poa = [
  { title: 'DURABLE POWER OF ATTORNEY' },
  { subtitle: 'Kentucky Uniform Power of Attorney Act, KRS Chapter 457' },
  { p: '**IMPORTANT INFORMATION.** This power of attorney authorizes another person (your agent) to make decisions concerning your property for you (the principal). Your agent will be able to make decisions and act with respect to your property (including your money) whether or not you are able to act for yourself. This power of attorney does not authorize the agent to make health care decisions for you. Your agent is entitled to reasonable compensation unless you state otherwise below. You should select someone you trust to serve as your agent. This power of attorney does not need to be filed, but it must be recorded with the County Clerk before your agent uses it to deal with real estate. Before signing this document, you should consult a lawyer of your choosing.' },
  { art: '1. DESIGNATION OF AGENT', text: [
    'I, [PRINCIPAL FULL LEGAL NAME], of [ADDRESS], [CITY], [COUNTY] County, Kentucky, name the following person as my agent:',
    'Name: [AGENT NAME]     Relationship: [RELATIONSHIP]',
    'Address: [ADDRESS]     Phone: [PHONE]',
  ] },
  { art: '2. DESIGNATION OF SUCCESSOR AGENTS', text: [
    'If my agent is unable or unwilling to act for me, I name, in the order listed, as my successor agents:',
    'First successor: [NAME], [ADDRESS], [PHONE]',
    'Second successor: [NAME], [ADDRESS], [PHONE]',
  ] },
  { art: '3. DURABILITY', text: 'This power of attorney is durable. It is not terminated by my subsequent incapacity or by lapse of time.' },
  { art: '4. EFFECTIVE DATE (initial ONE)', text: '' },
  { checks: [
    'This power of attorney is effective immediately upon signing.',
    'This power of attorney becomes effective only upon my incapacity, as determined in a signed writing by [one / two] licensed physician(s) who have examined me. Any third party may rely on that writing.',
  ] },
  { art: '5. GRANT OF GENERAL AUTHORITY', text: 'I grant my agent and any successor agent general authority to act for me with respect to the following subjects as defined in KRS Chapter 457. **Initial each subject you want to include.** To grant general authority over all subjects, you may initial “All Preceding Subjects” instead.' },
  { checks: [
    'Real Property',
    'Tangible Personal Property',
    'Stocks and Bonds',
    'Commodities and Options',
    'Banks and Other Financial Institutions',
    'Operation of an Entity or Business',
    'Insurance and Annuities',
    'Estates, Trusts, and Other Beneficial Interests',
    'Claims and Litigation',
    'Personal and Family Maintenance',
    'Benefits from Governmental Programs or Civil or Military Service',
    'Retirement Plans',
    'Taxes (including federal and Kentucky returns and representation before the IRS and Kentucky Department of Revenue)',
    'Digital Assets and electronic communications (KRS Chapter 369)',
    'ALL PRECEDING SUBJECTS',
  ] },
  { art: '6. GRANT OF SPECIFIC AUTHORITY (OPTIONAL)', text: 'My agent may NOT do any of the following specific acts for me UNLESS I have **initialed** the specific authority listed below (KRS 457.220). **Caution:** granting any of these powers will authorize your agent to take actions that could significantly reduce your property or change how it is distributed at your death.' },
  { checks: [
    'Create, amend, revoke, or terminate an inter vivos trust, including transferring my property to the [NAME] Irrevocable Trust',
    'Make a gift, subject to the limitations of KRS Chapter 457 and any special instructions in this power of attorney',
    'Create or change rights of survivorship',
    'Create or change a beneficiary designation',
    'Authorize another person to exercise the authority granted under this power of attorney',
    'Waive my right to be a beneficiary of a joint and survivor annuity, including a survivor benefit under a retirement plan',
    'Exercise fiduciary powers that I have authority to delegate',
    'Disclaim or refuse an interest in property, including a power of appointment',
  ] },
  { art: '7. LIMITATION ON AGENT’S AUTHORITY', text: 'An agent who is not my ancestor, spouse, or descendant may not use my property to benefit the agent or a person to whom the agent owes an obligation of support unless I have included that authority in the Special Instructions. My agent may not make, amend or revoke my will.' },
  { art: '8. SPECIAL INSTRUCTIONS (OPTIONAL)', text: [
    '[Gifts, if authorized above, are limited to the federal annual gift tax exclusion amount per recipient per calendar year, to the following persons: NAMES.]',
    '[Any other instructions or limits. Delete if none.]',
  ] },
  { art: '9. COMPENSATION AND REIMBURSEMENT', text: 'My agent is entitled to reimbursement of reasonable expenses incurred on my behalf and [is / is not] entitled to reasonable compensation.' },
  { art: '10. RECORDS AND ACCOUNTING', text: 'My agent shall keep a record of all receipts, disbursements and transactions made on my behalf and shall provide an accounting on request of me, a successor agent, or [NAME OF PERSON TO MONITOR].' },
  { art: '11. NOMINATION OF GUARDIAN OR CONSERVATOR', text: 'If it becomes necessary for a court to appoint a guardian or conservator of my estate or person, I nominate my agent, and then my successor agents in the order named.' },
  { art: '12. RELIANCE, COPIES AND PRIOR POWERS', text: 'A photocopy or electronically transmitted copy of this signed power of attorney has the same effect as the original. A person who in good faith accepts this power of attorney without actual knowledge that it is void, invalid or terminated is protected as provided in KRS Chapter 457. I revoke all prior general durable powers of attorney, except [NONE].' },
  { art: '13. GOVERNING LAW', text: 'This power of attorney is governed by the laws of the Commonwealth of Kentucky.' },
  { p: 'Signed on [DATE], at [CITY], Kentucky.', keepNext: true },
  { sig: ['[PRINCIPAL FULL LEGAL NAME], Principal', 'Address: [ADDRESS]'] },
  { h: 'NOTARY ACKNOWLEDGMENT' },
  ...notary('[PRINCIPAL FULL LEGAL NAME]', 'This Durable Power of Attorney'),
  { h: 'WITNESSES (recommended)' },
  { p: 'Each of us, being at least eighteen (18) years old and not named as an agent or successor agent, declares that the principal signed this instrument in our presence, appeared to be of sound mind and under no duress, and that we signed as witnesses in the principal’s presence on [DATE].', keepNext: true },
  { sig: ['Witness 1 signature', 'Printed name: [NAME]', 'Address: [ADDRESS]'] },
  { sig: ['Witness 2 signature', 'Printed name: [NAME]', 'Address: [ADDRESS]'] },
  { p: 'This instrument was prepared by: [NAME, ADDRESS] (required by KRS 382.335 if recorded).', run: { italics: true, size: 20 } },
  { pb: true },
  { title: 'AGENT’S ACKNOWLEDGMENT OF DUTIES' },
  { p: 'By acting or agreeing to act as the agent under this power of attorney, I assume the fiduciary and other legal responsibilities of an agent. I understand that I must: act in good faith; do nothing beyond the authority granted; act loyally for the principal’s benefit; avoid conflicts that would impair my ability to act in the principal’s best interest; disclose my identity as agent when I act for the principal by writing or signing “[PRINCIPAL] by [AGENT], as Agent”; act with care, competence and diligence; keep records of all receipts, disbursements and transactions; attempt to preserve the principal’s estate plan; keep the principal’s property separate from mine; and cooperate with the principal’s health care surrogate. I may resign by giving notice as provided in KRS Chapter 457.' },
  { sig: ['Agent signature: [AGENT NAME]', 'Date: [DATE]'] },
  { sig: ['Successor agent signature: [NAME]', 'Date: [DATE]'] },
];

// ---------------------------------------------------------------- 04 Irrevocable trust
const trust = [
  { title: 'THE [NAME] IRREVOCABLE TRUST' },
  { subtitle: 'Trust Agreement dated [DATE]' },
  { p: 'This Trust Agreement is made on [DATE], between [SETTLOR FULL LEGAL NAME], of [ADDRESS], [COUNTY] County, Kentucky, as settlor (the “Settlor”), and [TRUSTEE NAME], of [ADDRESS], as trustee (the “Trustee”). The Settlor is not married and has no children.' },
  { art: 'ARTICLE 1. NAME AND PURPOSE', text: 'This trust shall be known as “The [NAME] Irrevocable Trust dated [DATE].” Assets may be titled “[TRUSTEE NAME], Trustee of The [NAME] Irrevocable Trust dated [DATE].” The purpose of the trust is to hold, manage and distribute the trust property for the beneficiaries named in Article 4.' },
  { art: 'ARTICLE 2. IRREVOCABILITY', text: 'This trust is irrevocable. The Settlor expressly waives all rights and powers, whether alone or with others, and whether arising under this Agreement or under KRS Chapter 386B or other law, to revoke, amend, modify or terminate this Agreement or any trust created under it. The Settlor retains no beneficial interest in, and no power to direct the beneficial enjoyment of, the trust property, except as expressly provided in Article 12.' },
  { art: 'ARTICLE 3. TRUST PROPERTY', text: 'The Settlor transfers to the Trustee the property described on Schedule A, receipt of which the Trustee acknowledges. The Settlor or any other person may add property acceptable to the Trustee by lifetime gift, by will, or by beneficiary designation. All property held under this Agreement is the “trust estate.”' },
  { art: 'ARTICLE 4. BENEFICIARIES', text: [
    'The beneficiaries of this trust are: [NAME, RELATIONSHIP, DATE OF BIRTH]; [NAME, RELATIONSHIP, DATE OF BIRTH]; and [CHARITY NAME, EIN] (each a “Beneficiary”).',
    'The Settlor is not a beneficiary of this trust, and no part of the trust estate shall be distributed to or used for the benefit of the Settlor or to discharge any legal obligation of the Settlor.',
  ] },
  { art: 'ARTICLE 5. DISTRIBUTIONS DURING THE SETTLOR’S LIFETIME', text: 'During the Settlor’s lifetime, the Trustee may distribute to or for any individual Beneficiary so much of the net income and principal as the Trustee considers advisable for that Beneficiary’s health, education, maintenance and support, considering other resources known to the Trustee. Undistributed income shall be added to principal. [ALTERNATIVE: The Trustee shall accumulate all income and make no distributions during the Settlor’s lifetime.]' },
  { art: 'ARTICLE 6. DISTRIBUTION AT THE SETTLOR’S DEATH', text: [
    'Upon the Settlor’s death, the Trustee shall pay from the trust estate any amounts the Trustee considers advisable to the Settlor’s probate estate for taxes and expenses only if the Settlor’s other assets are insufficient, and shall then distribute the remaining trust estate as follows: [NAME] – [__]%; [NAME] – [__]%; [CHARITY NAME] – [__]%.',
    'If an individual Beneficiary is not then living, that Beneficiary’s share shall pass to that Beneficiary’s then-living descendants, per stirpes, or if none, to the other Beneficiaries proportionately. A share for a person under age [25] shall be held in a separate trust for that person under the standards of Article 5 and distributed outright at age [25].',
    'If no Beneficiary or descendant of an individual Beneficiary is then living, the trust estate shall be distributed to [ALTERNATE], or if none, to the persons who would inherit from the Settlor under the Kentucky laws of descent and distribution then in effect as though the Settlor had died unmarried and intestate.',
  ] },
  { art: 'ARTICLE 7. SPENDTHRIFT PROVISION', text: 'Each Beneficiary’s interest is held subject to a spendthrift trust. No Beneficiary may voluntarily or involuntarily transfer, assign, anticipate or encumber any interest in income or principal before actual receipt, and no interest shall be subject to the claims of a Beneficiary’s creditors, to attachment, garnishment or other legal process, to the fullest extent permitted by KRS Chapter 386B.' },
  { art: 'ARTICLE 8. TRUSTEES', text: [
    'The initial Trustee is [TRUSTEE NAME]. If the Trustee dies, resigns, becomes incapacitated or is removed, the following shall serve as successor Trustee in the order named: [SUCCESSOR TRUSTEE 1]; [SUCCESSOR TRUSTEE 2].',
    'If no named successor is able and willing to serve, a majority of the adult current Beneficiaries may appoint as successor Trustee an individual or a bank or trust company that is not related or subordinate to the Settlor within the meaning of Internal Revenue Code Section 672(c).',
    'The Settlor shall never serve as Trustee. A Trustee may resign by giving thirty (30) days’ written notice to the qualified Beneficiaries and any successor Trustee. Incapacity of an individual Trustee may be established by a written statement of a licensed physician.',
    'No bond shall be required of any Trustee. No Trustee shall be liable for any act or omission made in good faith, except for willful misconduct or gross negligence. A successor Trustee has no duty to examine the accounts of a prior Trustee.',
  ] },
  { art: 'ARTICLE 9. TRUSTEE POWERS', text: 'In addition to the powers conferred by KRS Chapter 386B, the Trustee may, without court order: retain, buy, sell, exchange, lease and mortgage real and personal property; invest under the Kentucky prudent investor rule; hold cash and open accounts; vote securities; borrow and lend; manage, repair and insure real estate; settle claims; employ and pay attorneys, accountants, investment advisers and other agents; divide or merge trusts with substantially identical terms; make distributions in cash or in kind, including on a non-pro-rata basis; make tax elections; and execute all documents necessary to carry out these powers.' },
  { art: 'ARTICLE 10. COMPENSATION', text: 'An individual Trustee [shall serve without compensation / is entitled to reasonable compensation]. A corporate Trustee is entitled to compensation under its published fee schedule. Each Trustee is entitled to reimbursement of reasonable expenses.' },
  { art: 'ARTICLE 11. ACCOUNTS AND INFORMATION', text: 'The Trustee shall keep accurate records and shall keep the qualified Beneficiaries reasonably informed about the administration of the trust, including by providing an annual report of trust property, liabilities, receipts and disbursements, as required by KRS Chapter 386B.' },
  { art: 'ARTICLE 12. TAX PROVISIONS', text: [
    'The Trustee shall obtain a federal employer identification number for the trust, file all required federal and Kentucky fiduciary income tax returns, and pay taxes from the trust estate.',
    '[CHOOSE ONE WITH TAX COUNSEL. Non-grantor option: The Settlor intends that this trust not be treated as a grantor trust for federal income tax purposes, and no power shall be exercised in a manner that would cause grantor-trust status.] [Grantor option: The Settlor reserves the power, exercisable in a nonfiduciary capacity and without the approval of any person in a fiduciary capacity, to reacquire trust property by substituting other property of equivalent value under Internal Revenue Code Section 675(4)(C), intending that the trust be a grantor trust for income tax purposes only. The Settlor may release this power by written notice to the Trustee.]',
  ] },
  { art: 'ARTICLE 13. PERPETUITIES', text: 'Notwithstanding any other provision, each trust created under this Agreement shall terminate no later than the latest date permitted by Kentucky law (KRS 381.215 to 381.225), and the remaining property shall be distributed to the persons then entitled to receive income, in proportion to their interests.' },
  { art: 'ARTICLE 14. GOVERNING LAW, SITUS AND MISCELLANEOUS', text: 'This Agreement shall be governed by the laws of the Commonwealth of Kentucky. The situs of administration is [COUNTY] County, Kentucky, and may be changed by the Trustee to another jurisdiction if in the best interests of the Beneficiaries, with notice to the qualified Beneficiaries. If any provision is invalid, the remaining provisions shall continue in effect. Headings are for convenience only. This Agreement may be signed in counterparts.' },
  { p: 'IN WITNESS WHEREOF, the Settlor and the Trustee have signed this Trust Agreement on the date first written above.', keepNext: true },
  { sig: ['[SETTLOR FULL LEGAL NAME], Settlor'] },
  { sig: ['[TRUSTEE NAME], Trustee'] },
  { h: 'ACKNOWLEDGMENT OF SETTLOR' },
  ...notary('[SETTLOR FULL LEGAL NAME], as Settlor', 'The foregoing Trust Agreement'),
  { h: 'ACKNOWLEDGMENT OF TRUSTEE' },
  ...notary('[TRUSTEE NAME], as Trustee', 'The foregoing Trust Agreement'),
  { pb: true },
  { title: 'SCHEDULE A' },
  { subtitle: 'Property transferred to The [NAME] Irrevocable Trust dated [DATE]' },
  { table: [
    ['Item', 'Description', 'How transferred', 'Approx. value'],
    ['Cash', 'Initial contribution', 'Check or deposit to trust account', '$[10.00]'],
    ['Real property', '[ADDRESS; PARCEL ID; DEED BOOK/PAGE]', 'Deed to Trustee, recorded with [COUNTY] County Clerk', '$[VALUE]'],
    ['Financial account', '[INSTITUTION, ACCOUNT TYPE, LAST 4 DIGITS]', 'Retitled in name of Trustee', '$[VALUE]'],
    ['Other', '[DESCRIPTION]', '[Assignment / title change]', '$[VALUE]'],
  ], widths: [1600, 3400, 2760, 1600] },
  { p: 'Settlor initials: ________     Trustee initials: ________     Date: [DATE]' },
];

Promise.all([
  build('00 - Kentucky Estate Plan - Review Notes and Signing Checklist.docx', checklist),
  build('01 - Last Will and Testament (Kentucky).docx', will, "Testator's initials: ________"),
  build('02 - Living Will Directive and Health Care Surrogate (Kentucky).docx', livingWill, "Grantor's initials: ________"),
  build('03 - Durable Power of Attorney (Kentucky).docx', poa, "Principal's initials: ________"),
  build('04 - Irrevocable Trust Agreement (Kentucky).docx', trust, 'Settlor initials: ______   Trustee initials: ______'),
]).then(() => console.log('done'));
