## **Iranian National ID Card**

Around 65 million Iranians hold the smart Iranian identity card (NID) or کارت ملی هوشمند [[1]](https://www.isna.ir/news/1403092215977/%D8%B9%D9%84%D8%AA-%D8%AA%D8%A3%D8%AE%DB%8C%D8%B1-%D8%AF%D8%B1-%D8%B5%D8%AF%D9%88%D8%B1-%DA%A9%D8%A7%D8%B1%D8%AA-%D9%87%D8%A7%DB%8C-%D9%85%D9%84%DB%8C-%DA%86%DB%8C%D8%B3%D8%AA).

National Organization for Civil Registration is the main body in charge of the NIDs and [Matiran Co.](https://www.linkedin.com/company/matiran/about/), is believed to be the main developer of (all or some parts of) the software on the cards.

We are currently investigating one of the Matiran's protected SDKs used by a 3rd party application [(Dastine)](pki.co.ir), and will gradually share our findings with you as we proceed. If you are interested in reverse-engineering next to us, an expert in smart cards, ex-employee of any of the named organisations having worked on the tech, please get in touch. Any contribution is greatly appriciated and hopefully can go a long way towards a demmocratic future for Iran. Your annonimity can be guaranteed.

## Unpacking Process
Matiran, the devoloper of the NID, has published a software development kit which can be found in its original form [here](./matiran-sdk/MDAS-Client_x64.dll).  
We decided to unpack the SDK and and reverse-engineer it to find the methods and APDU commands used to communicate with the card.

We had two option 2 do handle the protected library. a) decrypt the code statically, b) run the binary and dump it. To overcome the challenge of being caught after attaching a debugger to the EXE process we use a `scyllahide`.

We followed the execution of the program and checked for win32 API calls. This led us to the original entry point (OEP). For a packed binary, the entry point of the program will execute the "packer stub" instead of the original entry point, because it first needs to decrypt the packed code.

When the packed code was decrypted, finding the OEP was easy using `x64dbg`. At this point, we dumped the program using `Scylla`. Next we fixed the entry points in the PE headers manually using `PE-bear`.
Next we had to rebuild the import as they were simply wrong, so we dumped all the imported functions using x64dbg.
A custom tool were then used to dump the imports. Even with the dumped imports, some function names had to be manually inspected and fixed, and so did we.

Next was rebuilding the imports in the previously dumped file. For doing so we first added a custom section to the PE file. If you open the accompanied DLL file we linked below, you will see the section in "PE-bear" tool. We used this section to write new imports as packing had messed up the imports intentionally to prevent reverse engineering!

We used another custom tool specifically made for writing the imports, making changes to the PE structure, linking the new imports with the PE headers, and replacing the old ones.

Eventually we I had to verify every single imported function to make sure we had not made a mistake, and when verified, we were able to load the DLL into the memory successfully!

Unpacked [DLL](./assets/matiran-sdk/dump_oep-modified_sec_fixedIAT.dll).

---
### **National Developer of the Card OS (Matiran)**

* Technical docs from MatIran/ روال ارزيابي و مشخصات فني مورد نياز كارت خوان  
  * [اسكنر اثر انگشت و وبكم در سامانه بهره برداري از كارت هوشمند ملي](https://matiran.ir/wp-content/uploads/2024/02/021205-IRANID_Devices_Evaluation_100_15.1.pdf)	



### **Iran’s PKI**
* [PKI Status In Iran](https://www.asiapki.org/download/presentation/Iran-Updates-Sep2022.pdf)  
* Iran’s policies on digital certificates based on PKI: [سياست‌های گواهی الكترونيكی زيرساخت‌ كليد‌ عمومی كشور](https://drive.google.com/file/d/1V3SLn3pa-fy2uBMsOLw4NEWzHKZSb0uQ/view?usp=drive_link)

### **The Card:**

* NXP \- MIFARE type identification procedure  
  (ID Card has SAK=0x28 → type is “SmartMX with MiFARE classic 1k, basically a more modern card still supporting MiFARE interface)  
  * [MIFARE type identification procedure](https://www.nxp.com/docs/en/application-note/AN10833.pdf)   

* SmartMX brochure  
  * [SmartMX for programmable, high-security, multi-application smart cards](https://www.nxp.com/docs/en/brochure/75017515.pdf)  
  * [MIFARE Classic EV1 1K \- Mainstream contactless smart card IC for fast and easy solution development](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)	

### **Card Readers & Devices:** 

* [NFC Reader/NFC Writer ACR1252U USB NFC III](https://www.amazon.de/ACR1252U-Kartenleseger%C3%A4t-Forum-Zertifiziert-kompatibel-RFID-Card/dp/B01KIKBYAG)  

####
* [https://www.futronic-tech.com/](https://www.biometricsupply.com/product/futronic-fs10/)  
* [https://www.logidata-int.fr/en/26-epass3003.html](https://www.logidata-int.fr/en/26-epass3003.html)   

  
### **Documents**

* [iranians.vote's library](https://drive.google.com/drive/folders/1vamnbryw-yCLyn6ZYDjRnkkgBhg9DF_I?usp=drive_link) (ask for permission)  
    
* **Standards**  
  * Iran National Standards Organization ICS:35.240.15 (we suspect analogues to or accompanying ISO 14443-4). National ID Cards are implemented according to this standard, however the specification looks too broad and generic to be useful: [https://shaghool.ir/Files/services-16386-3.pdf](https://shaghool.ir/Files/services-16386-3.pdf)  
  * Majles Research Center report of ID Card project status and challenges:  [ارزیابی پروژه صدور كارت هوشمند ملی و ارائه پيشنهادات سياستی](https://www.sid.ir/fileserver/pf/majles/17269.pdf)  


### **Reports**
We gradually report about decisions made, methods used, and our findings [here](./reports/).