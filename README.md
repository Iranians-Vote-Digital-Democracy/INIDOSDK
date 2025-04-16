## **OPEN SDK for IRANIAN NATIONAL IDENTITY CARD**

More than 63 million Iranians hold the Iranian National Identity smart card (NID).
Goal of this project is to create _zero-knowledge proofs_ of identity, using the NID. For more information pleasse read our [paper](https://docs.google.com/document/d/18kjUKhLuJ0IfRMrl2NZBXwipya2fKVqmXfLsZpZE9bQ/) and visit our [main project](https://github.com/Iranians-Vote-Digital-Democracy).

National Organization for Civil Registration is the main body in charge of the NIDs in Iran, and [Matiran Co.](https://www.linkedin.com/company/matiran/about/), is the main developer of the software related to the cards. The state-developed SDK we worked on in this project is responsible for communicating with the card.

We are investigating Matiran's protected SDK which is used by 3rd party KYC and Digital signatures services e.g. [Dastine](pki.co.ir).

## **CURRENT STATUS**

- Published a comprehensive reverse-engineering. Find it [here](./docs/Report.md).
- Implemented [code to read](./src/read/) X509 certificates, CSN, CRN, AFIS, meta FEID, personal info, SOD, and get version.
     
## **RESOURCES**

IDA databases:
- [Matiran SDK](./matiran-sdk/MDAS_IDB_10.04.2025.zip)  
- [Dastine](./dastine/Dastine.exe.i64.zip)

## **TEST ON YOUR CARD**

- Mobile [App](https://github.com/Iranians-Vote-Digital-Democracy/INIDCA) (Android)
- Desktop [C++ code](./src/)

## **CERTIFICATE CHAIN VALIDATION**
- [test_cert_validation](./test_cert_chain/README.md)

## **FURTHER READING**

- [Iran’s PKI policies on digital certificates](https://drive.google.com/file/d/1V3SLn3pa-fy2uBMsOLw4NEWzHKZSb0uQ/view?usp=drive_link) (Persian)

- [Identification cards, Integrated circuit card programming interfaces, Part 3 : Application interface](https://shaghool.ir/Files/services-16386-3.pdf) (Persian)

- [The evaluation of the National Smart Card Issuance Project and the presentation of policy recommendations](https://www.sid.ir/fileserver/pf/majles/17269.pdf)(Persian)

