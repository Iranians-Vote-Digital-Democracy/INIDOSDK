
## Flows:
```flowdoc 
1) load_library export function()
 *v0 = &off_180D31690;
 *(v0 + 8) = &MDIS_SDK::MDISClient::`vftable';
 *(vo + 0x10) = &MDIS_SDK::DeviceInfo::`vftable';
 *(v0 + 0x90) = &MDIS_SDK::UiOptions::`vftable';
 
  sub_18036B190(v0 + 1);
  return v0;
  
- sub_18036B190()

	init_MDIS_180026E70();
		remove("Pardis.txt"), remove("Mav2.txt"), remove("Mav3.txt"), remove("Mav4.txt"), remove("mdaslog.txt")
		call constructor of Pardis_PIS_2::Pardis_PIS_2(v16, a2, v22); create three Pardis--->v13 = Omid::Omid(v11, *(_QWORD *)a1, (unsigned int)v25, v12, (__int64)v22);
		
		
2) get_new_instance export function(PVOID MDAS_SDK_Instance, Int type)

==sub_18031B6F0(PVOID MDAS_SDK_Instance, int type)
type == 700 --> create instance of Service_UnblockPin_v1, size is 0x4A0
type == 820 --> create instance of Service_Registration_v1, size is 0x248
type == 830 --> create instance of Service_GetCardCapability_v1, size is 0xA8
type == 650 --> create instance of Service_Sign_v1, size is 0x5D8
type == 10 --> create instance of Service_ChangePin_v1, size is 0x3A0
type == 520 --> Service_Initialize_v1, 0x1C0
type == 610 --> Service_GetMocFingerIndex_v1, 0xA0
type == 630 --> Service_Authenticate_v1, 0x528
type == 32 --> MDIS_SDK::CardCapabilityResult, 0x98
type == 500 --> MDIS_SDK::DeviceInfo, 0x68
....

3) execute export function()


4) set_parameter function(handle, Service_Authenticate_v1 inst) 
_7Service_Authenticate_v1@@6B@;; 180D36780





Dastine.exe--->if command is "NIDAuthenticateByPIN"

code:
	if ( (unsigned __int8)sub_140069C20(&v582, "NIDAuthenticateByPIN") )
      {
        v72 = sub_14004D090(v714, L"cardReader");
        v73 = sub_14004CA30(v879, &Source);
        sub_1400D28E0(v651, v73, v72);
        v74 = sub_14006D6E0(v651);
        sub_140065D40(v2, v597, v74);
        v583 = v1077;
        sub_14004CA30(v881, v597);
        v75 = sub_1400CE200(v922);
        v76 = sub_14004C270(v1077, "Result");
        v77 = sub_140069E70(v1235, Block);
        v78 = sub_1400D4690(v1350, v77, v76, v75);
        sub_140069F30(Block, v78);
        sub_14004C2B0(v1350);
        sub_14004CB80(v597);
        sub_14004CB80(v651);
        goto LABEL_243;
      }
	  
Read cardReader name from console.
NIDAuthenticateByPIN(smartCardReaderName); //Authenticates by PIN of national Id card. A dialog box is displayed for enter PIN.

NIDAuthenticateByPIN_main_140065D40(smartCardReaderName)
AuthenticateByPIN_1400BDA30()

	initialize_service_1400BC500()
		"3082056D30820355A003020102021211215AA3DF829CAA96EE8F76B73B65DD8AD7300D06092A864886F70D01010B0500303F310B300906035504"
		"061302495231183016060355040A0C0F4972616E20476F7665726E6D656E743116301406035504030C0D4952414E20526F6F7420434131301E17"
		"0D3132303932333030303030305A170D3332303932333030303030305A303F310B300906035504061302495231183016060355040A0C0F497261"
		"6E20476F7665726E6D656E743116301406035504030C0D4952414E20526F6F742043413130820222300D06092A864886F70D0101010500038202"
		"0F003082020A0282020100BE8184598317797134FF9EB53912CF0B2C8D145E57B948769539092D176AA7B870EBF70EA058B30A81BFD1D1628589"
		"794CC95F94A88E4B04DFCB16B711D9F5F813A039FB7E7C619BADC76774DD750C07BA79E11B95E390849348EC300CDE032C3D2D3AD434C933AD41"
		"2CC167CD7B5AAD78AA25B7ED556A61A4061628469200FA0E7F61E80F35B884D566D8D1D91AB70467CE248F037F6CF06782C48527D538DB4CC556"
		"C3B70DA92AFF6E2CCE6710E5A841D1B0A2E84FA2C1BCA6F62A622245B5ACDA8E6F151E50CCDC7EDE0B055FB12E5E9364EDE97C9A1C366BCFE731"
		"5DD5A3026684FA0E243043E7D93D3C4D7649BA8C8A942B903EA2FB3CB7FDD931677667F72194E76CB04DB7A3A378B4BABAF3D499CAAC5AD6FEBC"
		"74463BA0A6789AC989F897AFAB683437931441DB0C51ACA74AD527CE8DE218179E88EDEFF3F080D778FCA07BC7AD5357F48DD08866460063CE16"
		"C7C66F9BD85A5FE764E9EB6AA23846EC295329B00061BD457099E5F954C2343DA06E8932BDD1103A52AF9C29FAE01E3BD7E2EF802E24650EB813"
		"2618955DD20F845503FF71E1C93D258A8B352978A01D22BB8FB65211A0B3701ECB927E41A9312B6B96EFE32FA2C9C3C7ECCDF4EB163352767667"
		"A2B3A920A5AE86BF310E6EE8ED76CD3760242EE624E47D65451A8980386BCCAA3B6785F236490265B78CEAE5FA69434C665F681C58C29A331FBC"
		"F50203010001A3633061300E0603551D0F0101FF040403020106300F0603551D130101FF040530030101FF301D0603551D0E04160414DCB80086"
		"6DFD0C3D4E784E18E4B538498EC8DEB4301F0603551D23041830168014DCB800866DFD0C3D4E784E18E4B538498EC8DEB4300D06092A864886F7"
		"0D01010B050003820201008073046E3EA7BD285862F7A41D9764EE7DEE59696058F47D9AEFBB624EE477F8D8733417DBA36042303E429A79A030"
		"7108967FDB6F6D3582EAA2F6DCB2CC4EA07AF07E298165471901B5AFE86340476332065D4BB98532BD15CBD5829A287031EF06374CE667767F5F"
		"43B5EC3ADC2C8E6C0E4D3BBF3810331A333660E3D55AC7F58A3E65C8EA764E60A279BCDCE9E3CA0FF85AF23E0B450E4C726C95BD5336EAC7C3AE"
		"CDEBC37C633D17517A2898306FF8A7B788FD704411F377AB23DA189E0896519B2DE375BBBFE0373980F37F93271BF4E41AD46C896065478AE331"
		"B8B2874F580C28C43D2C2BF7F453E0F279215EE76356743601734397E994C6461FB414A32FD0E3EDB8012C5CE4331EE8F66515C9FE5FB55E7DD0"
		"7F99BE89DB8E68CBF4E99A0D1DCF0A063CA7C88C4095D8A367A53321C9B510E471261121C0FAA8CF7C9610EDB7678238568EB6023A6A36BF1914"
		"11AC03CBD979972A67203ABDC6A126F6C7D17FA691DB7B17E1B67538ACB6C63CA2F4124A5E165B4A7A91FD05A09AE06B3C1506467E0D63903252"
		"1900F2596BAE2B4205AE8BE9BF30EA37A3BA51A1FD36258E2D183BA74149C12BE73CE9AB838C21D71AF6A926109ECD512245AC0AE803927175FF"
		"08B2CB45CC50B067E5E769E8C4C410DC022FDFC840E0B276014020E1A93E2368C63C9FF6DC97C097229D4DF1F4EDA9F69F61A3E2EB6F10C4DBEAB3"
		
		
		CA_Name: "IRAN Digital ID CA2"
		"IRAN Digital Citizen CA 20"
		
		Load_MDAS_Client_x64_dll_1400BB6F0("NID/v6/MDAS-Client_x64.dll");
		mdas_load_library_1404D25E0()
		execute_initialize_command_1400BBB40()
			Service_Initialize_v1 inst = set_parameters_for_initialize_service_1400AB890()
				DeviceInfo = deviceinfo_setparameter_1400AA430()
					DeviceInfo = mdas_get_new_instance_1404D25D0(500); 500: MDIS_SDK::DeviceInfo, 0x68, MDIS_SDK::DeviceInfo::`vftable'
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, DeviceInfo, 502LL, CardReaderName); //set_device_info|set_parameter|DeviceInfo_CardReaderName
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, DeviceInfo, 503LL, FingerScannerName); //set_device_info|set_parameter|DeviceInfo_FingerScannerName
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, DeviceInfo, 504LL, CameraName); //set_device_info|set_parameter|DeviceInfo_CameraName
					return DeviceInfo;
					
				UiOptions = uioption_setparameter_1400AB000()
					UiOptions = mdas_get_new_instance_1404D25D0(a1, 430LL); 430: MDIS_SDK::UiOptions, 0x68, MDIS_SDK::UiOptions::`vftable'
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 432LL, ShowPinInputUI = 1) //set_ui_options|set_parameter|UiOptions_ShowPinInputUI
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 433LL, ShowFingerPrintUI = 0) //set_ui_options|set_parameter|UiOptions_ShowFingerPrintUI
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 434LL, ShowFaceInputUI = 0) //set_ui_options|set_parameter|UiOptions_ShowFaceInputUI
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 438LL, BackgroundColor) //set_ui_options|set_parameter|UiOptions_BackgroundColor
						BackgroundColor = mdas_get_new_instance_1404D25D0(370); 370: MDIS_SDK::Color, 0x18, MDIS_SDK::Color::`vftable'
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, BackgroundColor, 372LL, 0xFFFFFFFF) //set_background_color|background_color|set_parameter|Color_Red
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, BackgroundColor, 373LL, 0xFFFFFF80) //set_background_color|background_color|set_parameter|Color_Green
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, BackgroundColor, 374LL, 0x40) //set_background_color|background_color|set_parameter|Color_Blue
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 437LL, WindowLocation) //set_ui_options|set_parameter|UiOptions_WindowLocation
						WindowLocation = mdas_get_new_instance_1404D25D0(410); 410: MDIS_SDK::WindowLocation, 0x10, MDIS_SDK::WindowLocation::`vftable'
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, WindowLocation, 412LL, 100) //set_window_location|set_parameter|WindowLocation_X
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, WindowLocation, 413LL, 100) //set_window_location|set_parameter|WindowLocation_Y
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 436LL, WindowSize) //set_ui_options|set_parameter|UiOptions_WindowSize
						WindowSize = mdas_get_new_instance_1404D25D0(390); 390: MDIS_SDK::WindowSize, 0x10, MDIS_SDK::WindowSize::`vftable'(off_180D378A0 in MDAS-Client_x64.dll)
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, WindowSize, 392LL, 50) //set_window_size|set_parameter|WindowSize_Width
						mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, WindowSize, 393LL, 50) //set_window_size|set_parameter|WindowSize_Height
					mdas_set_parameter_1404D25C0(MDAS_SDK_Handle, UiOptions, 439LL, HeaderImage) //set_ui_options|set_parameter|UiOptions_HeaderImage
						 strcpy_s(HeaderImage, 0x2801uLL, v2); //set_ui_options|convert_string|header_image
					
					return UiOptions;
					
					
				Service_Initialize_v1 inst = mdas_get_new_instance_1404D25D0(520); 520: Service_Initialize_v1, 0x1C0, Service_Initialize_v1::`vftable'
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_ServerAddress")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_ServerUserName")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_ServerPassWord")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_DeviceInfo")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_UiOptions")
			
			mdas_execute_1404D25B0(MDAS_SDK_Handle handle, Service_Initialize_v1 inst ) //initialize_service|execute|Initialize_v1
			
				//in MDAS-Client_x64.dll
				execute_18031B6C0(MDAS_SDK_Handle, Service_Initialize_v1)
					//seg002:0000000180D361E0 ; const Service_Initialize_v1::`vftable'
					//seg002:0000000180D361E0 ??_7Service_Initialize_v1@@6B@ dq offset sub_1803798E0
					
					//*(QWORD*)(Service_Initialize_v1 + 0x18) = sub_180379910
				
			print_initialize_result_1400A91F0
	
	if initialize_service_1400BC500 succeded
		Authenticate_v1_1400BCC10()
			set_parameters_for_authenticate_1400AF5D0()
				
				
				mdas_get_new_instance_1404D25D0(630); 630: Service_Authenticate_v1, 0x528
					LevelOfAssurance = mdas_get_new_instance_1404D25D0(480); 480: MDIS_SDK::LevelOfAssurance, 0x18, MDIS_SDK::LevelOfAssurance::`vftable'
						mdas_set_parameter_1404D25C0(LevelOfAssurance, "set_level_of_assurance|set_parameter|LevelOfAssurance_AuthenticationMethod")
						mdas_set_parameter_1404D25C0(LevelOfAssurance, "set_level_of_assurance|set_parameter|LevelOfAssurance_FaceMatchingSeverity")
						mdas_set_parameter_1404D25C0(LevelOfAssurance, "set_level_of_assurance|set_parameter|LevelOfAssurance_RevocationCheck")
						mdas_set_parameter_1404D25C0(LevelOfAssurance, "set_level_of_assurance|set_parameter|LevelOfAssurance_AuthorizationCheck")
					
					Credentials = mdas_get_new_instance_1404D25D0(350); 350: MDIS_SDK::Credentials, 0x140, MDIS_SDK::Credentials::`vftable'
						FaceData = mdas_get_new_instance_1404D25D0(657); 657: MDIS_SDK::FaceData, 0x38, MDIS_SDK::FaceData::`vftable'
						mdas_set_parameter_1404D25C0(sdk_handle, Credentials, 356LL, FaceData) //set_credentials|set_parameter|Credentials_FaceData
					
				mdas_set_parameter_1404D25C0("set_authentication_service_parameters|set_parameter|Authenticate_v1_Loa", LevelOfAssurance)
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_ServerUserName")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_ServerPassWord")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_DeviceInfo")
				mdas_set_parameter_1404D25C0("set_initialize_service|set_parameter|Initialize_v1_UiOptions")
				
			if set_parameters_for_authenticate_1400AF5D0()
				mdas_execute_1404D25B0("authenticate_service|execute|Authenticate_v1")
	
Please look at: https://dastine.pki.co.ir/doxygen/class_dastine.html#a06a3fda90c39e2f4b40ac0d68d597dbc

```