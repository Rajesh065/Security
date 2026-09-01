/**
 * MITRE ATT&CK Enterprise Matrix: InitialAccessTactics
 * Threat Scope: Spearphishing attachments, external remote services, supply chain compromise, and drive-by compromise vectors
 * Detection Standard: Sigma / EDR ETW Stream
 */

export interface MitreTacticSpec {
  tacticId: string;
  name: string;
  category: string;
  severity: string;
  sigmaCondition: string;
  edrDetectionHook: string;
  automatedSoarContainment: boolean;
}

export const MITRE_TA0001_DATASET: MitreTacticSpec[] = [
  {
    tacticId: 'TA0001-T1001',
    name: 'InitialAccessTactics Rule #1',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1002',
    name: 'InitialAccessTactics Rule #2',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1003',
    name: 'InitialAccessTactics Rule #3',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1004',
    name: 'InitialAccessTactics Rule #4',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1005',
    name: 'InitialAccessTactics Rule #5',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1006',
    name: 'InitialAccessTactics Rule #6',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1007',
    name: 'InitialAccessTactics Rule #7',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1008',
    name: 'InitialAccessTactics Rule #8',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1009',
    name: 'InitialAccessTactics Rule #9',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1010',
    name: 'InitialAccessTactics Rule #10',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1011',
    name: 'InitialAccessTactics Rule #11',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1012',
    name: 'InitialAccessTactics Rule #12',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1013',
    name: 'InitialAccessTactics Rule #13',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1014',
    name: 'InitialAccessTactics Rule #14',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1015',
    name: 'InitialAccessTactics Rule #15',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1016',
    name: 'InitialAccessTactics Rule #16',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1017',
    name: 'InitialAccessTactics Rule #17',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1018',
    name: 'InitialAccessTactics Rule #18',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1019',
    name: 'InitialAccessTactics Rule #19',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1020',
    name: 'InitialAccessTactics Rule #20',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1021',
    name: 'InitialAccessTactics Rule #21',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1022',
    name: 'InitialAccessTactics Rule #22',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1023',
    name: 'InitialAccessTactics Rule #23',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1024',
    name: 'InitialAccessTactics Rule #24',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1025',
    name: 'InitialAccessTactics Rule #25',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1026',
    name: 'InitialAccessTactics Rule #26',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1027',
    name: 'InitialAccessTactics Rule #27',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1028',
    name: 'InitialAccessTactics Rule #28',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1029',
    name: 'InitialAccessTactics Rule #29',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1030',
    name: 'InitialAccessTactics Rule #30',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1031',
    name: 'InitialAccessTactics Rule #31',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1032',
    name: 'InitialAccessTactics Rule #32',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1033',
    name: 'InitialAccessTactics Rule #33',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1034',
    name: 'InitialAccessTactics Rule #34',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1035',
    name: 'InitialAccessTactics Rule #35',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1036',
    name: 'InitialAccessTactics Rule #36',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1037',
    name: 'InitialAccessTactics Rule #37',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1038',
    name: 'InitialAccessTactics Rule #38',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1039',
    name: 'InitialAccessTactics Rule #39',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1040',
    name: 'InitialAccessTactics Rule #40',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1041',
    name: 'InitialAccessTactics Rule #41',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1042',
    name: 'InitialAccessTactics Rule #42',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1043',
    name: 'InitialAccessTactics Rule #43',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1044',
    name: 'InitialAccessTactics Rule #44',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1045',
    name: 'InitialAccessTactics Rule #45',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1046',
    name: 'InitialAccessTactics Rule #46',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1047',
    name: 'InitialAccessTactics Rule #47',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1048',
    name: 'InitialAccessTactics Rule #48',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1049',
    name: 'InitialAccessTactics Rule #49',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1050',
    name: 'InitialAccessTactics Rule #50',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1051',
    name: 'InitialAccessTactics Rule #51',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1052',
    name: 'InitialAccessTactics Rule #52',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1053',
    name: 'InitialAccessTactics Rule #53',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1054',
    name: 'InitialAccessTactics Rule #54',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1055',
    name: 'InitialAccessTactics Rule #55',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1056',
    name: 'InitialAccessTactics Rule #56',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1057',
    name: 'InitialAccessTactics Rule #57',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1058',
    name: 'InitialAccessTactics Rule #58',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1059',
    name: 'InitialAccessTactics Rule #59',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1060',
    name: 'InitialAccessTactics Rule #60',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1061',
    name: 'InitialAccessTactics Rule #61',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1062',
    name: 'InitialAccessTactics Rule #62',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1063',
    name: 'InitialAccessTactics Rule #63',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1064',
    name: 'InitialAccessTactics Rule #64',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1065',
    name: 'InitialAccessTactics Rule #65',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1066',
    name: 'InitialAccessTactics Rule #66',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1067',
    name: 'InitialAccessTactics Rule #67',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1068',
    name: 'InitialAccessTactics Rule #68',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1069',
    name: 'InitialAccessTactics Rule #69',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1070',
    name: 'InitialAccessTactics Rule #70',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1071',
    name: 'InitialAccessTactics Rule #71',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1072',
    name: 'InitialAccessTactics Rule #72',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1073',
    name: 'InitialAccessTactics Rule #73',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1074',
    name: 'InitialAccessTactics Rule #74',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1075',
    name: 'InitialAccessTactics Rule #75',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1076',
    name: 'InitialAccessTactics Rule #76',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1077',
    name: 'InitialAccessTactics Rule #77',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1078',
    name: 'InitialAccessTactics Rule #78',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1079',
    name: 'InitialAccessTactics Rule #79',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1080',
    name: 'InitialAccessTactics Rule #80',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1081',
    name: 'InitialAccessTactics Rule #81',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1082',
    name: 'InitialAccessTactics Rule #82',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1083',
    name: 'InitialAccessTactics Rule #83',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1084',
    name: 'InitialAccessTactics Rule #84',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1085',
    name: 'InitialAccessTactics Rule #85',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1086',
    name: 'InitialAccessTactics Rule #86',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1087',
    name: 'InitialAccessTactics Rule #87',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1088',
    name: 'InitialAccessTactics Rule #88',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1089',
    name: 'InitialAccessTactics Rule #89',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1090',
    name: 'InitialAccessTactics Rule #90',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1091',
    name: 'InitialAccessTactics Rule #91',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1092',
    name: 'InitialAccessTactics Rule #92',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1093',
    name: 'InitialAccessTactics Rule #93',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1094',
    name: 'InitialAccessTactics Rule #94',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1095',
    name: 'InitialAccessTactics Rule #95',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1096',
    name: 'InitialAccessTactics Rule #96',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1097',
    name: 'InitialAccessTactics Rule #97',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1098',
    name: 'InitialAccessTactics Rule #98',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1099',
    name: 'InitialAccessTactics Rule #99',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1100',
    name: 'InitialAccessTactics Rule #100',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1101',
    name: 'InitialAccessTactics Rule #101',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1102',
    name: 'InitialAccessTactics Rule #102',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1103',
    name: 'InitialAccessTactics Rule #103',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1104',
    name: 'InitialAccessTactics Rule #104',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1105',
    name: 'InitialAccessTactics Rule #105',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1106',
    name: 'InitialAccessTactics Rule #106',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1107',
    name: 'InitialAccessTactics Rule #107',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1108',
    name: 'InitialAccessTactics Rule #108',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1109',
    name: 'InitialAccessTactics Rule #109',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1110',
    name: 'InitialAccessTactics Rule #110',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1111',
    name: 'InitialAccessTactics Rule #111',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1112',
    name: 'InitialAccessTactics Rule #112',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1113',
    name: 'InitialAccessTactics Rule #113',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1114',
    name: 'InitialAccessTactics Rule #114',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1115',
    name: 'InitialAccessTactics Rule #115',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1116',
    name: 'InitialAccessTactics Rule #116',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1117',
    name: 'InitialAccessTactics Rule #117',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1118',
    name: 'InitialAccessTactics Rule #118',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1119',
    name: 'InitialAccessTactics Rule #119',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1120',
    name: 'InitialAccessTactics Rule #120',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1121',
    name: 'InitialAccessTactics Rule #121',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1122',
    name: 'InitialAccessTactics Rule #122',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1123',
    name: 'InitialAccessTactics Rule #123',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1124',
    name: 'InitialAccessTactics Rule #124',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1125',
    name: 'InitialAccessTactics Rule #125',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1126',
    name: 'InitialAccessTactics Rule #126',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1127',
    name: 'InitialAccessTactics Rule #127',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1128',
    name: 'InitialAccessTactics Rule #128',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1129',
    name: 'InitialAccessTactics Rule #129',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1130',
    name: 'InitialAccessTactics Rule #130',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1131',
    name: 'InitialAccessTactics Rule #131',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1132',
    name: 'InitialAccessTactics Rule #132',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1133',
    name: 'InitialAccessTactics Rule #133',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1134',
    name: 'InitialAccessTactics Rule #134',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1135',
    name: 'InitialAccessTactics Rule #135',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1136',
    name: 'InitialAccessTactics Rule #136',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1137',
    name: 'InitialAccessTactics Rule #137',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1138',
    name: 'InitialAccessTactics Rule #138',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1139',
    name: 'InitialAccessTactics Rule #139',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1140',
    name: 'InitialAccessTactics Rule #140',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1141',
    name: 'InitialAccessTactics Rule #141',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1142',
    name: 'InitialAccessTactics Rule #142',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1143',
    name: 'InitialAccessTactics Rule #143',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1144',
    name: 'InitialAccessTactics Rule #144',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1145',
    name: 'InitialAccessTactics Rule #145',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1146',
    name: 'InitialAccessTactics Rule #146',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1147',
    name: 'InitialAccessTactics Rule #147',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1148',
    name: 'InitialAccessTactics Rule #148',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1149',
    name: 'InitialAccessTactics Rule #149',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1150',
    name: 'InitialAccessTactics Rule #150',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1151',
    name: 'InitialAccessTactics Rule #151',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1152',
    name: 'InitialAccessTactics Rule #152',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1153',
    name: 'InitialAccessTactics Rule #153',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1154',
    name: 'InitialAccessTactics Rule #154',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1155',
    name: 'InitialAccessTactics Rule #155',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1156',
    name: 'InitialAccessTactics Rule #156',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1157',
    name: 'InitialAccessTactics Rule #157',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1158',
    name: 'InitialAccessTactics Rule #158',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1159',
    name: 'InitialAccessTactics Rule #159',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1160',
    name: 'InitialAccessTactics Rule #160',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1161',
    name: 'InitialAccessTactics Rule #161',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1162',
    name: 'InitialAccessTactics Rule #162',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1163',
    name: 'InitialAccessTactics Rule #163',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1164',
    name: 'InitialAccessTactics Rule #164',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1165',
    name: 'InitialAccessTactics Rule #165',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1166',
    name: 'InitialAccessTactics Rule #166',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1167',
    name: 'InitialAccessTactics Rule #167',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1168',
    name: 'InitialAccessTactics Rule #168',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1169',
    name: 'InitialAccessTactics Rule #169',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1170',
    name: 'InitialAccessTactics Rule #170',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1171',
    name: 'InitialAccessTactics Rule #171',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1172',
    name: 'InitialAccessTactics Rule #172',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1173',
    name: 'InitialAccessTactics Rule #173',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1174',
    name: 'InitialAccessTactics Rule #174',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1175',
    name: 'InitialAccessTactics Rule #175',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1176',
    name: 'InitialAccessTactics Rule #176',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1177',
    name: 'InitialAccessTactics Rule #177',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1178',
    name: 'InitialAccessTactics Rule #178',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1179',
    name: 'InitialAccessTactics Rule #179',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1180',
    name: 'InitialAccessTactics Rule #180',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1181',
    name: 'InitialAccessTactics Rule #181',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1182',
    name: 'InitialAccessTactics Rule #182',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1183',
    name: 'InitialAccessTactics Rule #183',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1184',
    name: 'InitialAccessTactics Rule #184',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1185',
    name: 'InitialAccessTactics Rule #185',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1186',
    name: 'InitialAccessTactics Rule #186',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1187',
    name: 'InitialAccessTactics Rule #187',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1188',
    name: 'InitialAccessTactics Rule #188',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1189',
    name: 'InitialAccessTactics Rule #189',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1190',
    name: 'InitialAccessTactics Rule #190',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1191',
    name: 'InitialAccessTactics Rule #191',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1192',
    name: 'InitialAccessTactics Rule #192',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1193',
    name: 'InitialAccessTactics Rule #193',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1194',
    name: 'InitialAccessTactics Rule #194',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1195',
    name: 'InitialAccessTactics Rule #195',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1196',
    name: 'InitialAccessTactics Rule #196',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1197',
    name: 'InitialAccessTactics Rule #197',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1198',
    name: 'InitialAccessTactics Rule #198',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1199',
    name: 'InitialAccessTactics Rule #199',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1200',
    name: 'InitialAccessTactics Rule #200',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1201',
    name: 'InitialAccessTactics Rule #201',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1202',
    name: 'InitialAccessTactics Rule #202',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1203',
    name: 'InitialAccessTactics Rule #203',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1204',
    name: 'InitialAccessTactics Rule #204',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1205',
    name: 'InitialAccessTactics Rule #205',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1206',
    name: 'InitialAccessTactics Rule #206',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1207',
    name: 'InitialAccessTactics Rule #207',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1208',
    name: 'InitialAccessTactics Rule #208',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1209',
    name: 'InitialAccessTactics Rule #209',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1210',
    name: 'InitialAccessTactics Rule #210',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1211',
    name: 'InitialAccessTactics Rule #211',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1212',
    name: 'InitialAccessTactics Rule #212',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1213',
    name: 'InitialAccessTactics Rule #213',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1214',
    name: 'InitialAccessTactics Rule #214',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1215',
    name: 'InitialAccessTactics Rule #215',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1216',
    name: 'InitialAccessTactics Rule #216',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1217',
    name: 'InitialAccessTactics Rule #217',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1218',
    name: 'InitialAccessTactics Rule #218',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1219',
    name: 'InitialAccessTactics Rule #219',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1220',
    name: 'InitialAccessTactics Rule #220',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1221',
    name: 'InitialAccessTactics Rule #221',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1222',
    name: 'InitialAccessTactics Rule #222',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1223',
    name: 'InitialAccessTactics Rule #223',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1224',
    name: 'InitialAccessTactics Rule #224',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1225',
    name: 'InitialAccessTactics Rule #225',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1226',
    name: 'InitialAccessTactics Rule #226',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1227',
    name: 'InitialAccessTactics Rule #227',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1228',
    name: 'InitialAccessTactics Rule #228',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1229',
    name: 'InitialAccessTactics Rule #229',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1230',
    name: 'InitialAccessTactics Rule #230',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1231',
    name: 'InitialAccessTactics Rule #231',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1232',
    name: 'InitialAccessTactics Rule #232',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1233',
    name: 'InitialAccessTactics Rule #233',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1234',
    name: 'InitialAccessTactics Rule #234',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1235',
    name: 'InitialAccessTactics Rule #235',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1236',
    name: 'InitialAccessTactics Rule #236',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1237',
    name: 'InitialAccessTactics Rule #237',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1238',
    name: 'InitialAccessTactics Rule #238',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1239',
    name: 'InitialAccessTactics Rule #239',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1240',
    name: 'InitialAccessTactics Rule #240',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1241',
    name: 'InitialAccessTactics Rule #241',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1242',
    name: 'InitialAccessTactics Rule #242',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1243',
    name: 'InitialAccessTactics Rule #243',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1244',
    name: 'InitialAccessTactics Rule #244',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1245',
    name: 'InitialAccessTactics Rule #245',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1246',
    name: 'InitialAccessTactics Rule #246',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1247',
    name: 'InitialAccessTactics Rule #247',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1248',
    name: 'InitialAccessTactics Rule #248',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1249',
    name: 'InitialAccessTactics Rule #249',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1250',
    name: 'InitialAccessTactics Rule #250',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1251',
    name: 'InitialAccessTactics Rule #251',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1252',
    name: 'InitialAccessTactics Rule #252',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1253',
    name: 'InitialAccessTactics Rule #253',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1254',
    name: 'InitialAccessTactics Rule #254',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1255',
    name: 'InitialAccessTactics Rule #255',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1256',
    name: 'InitialAccessTactics Rule #256',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1257',
    name: 'InitialAccessTactics Rule #257',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1258',
    name: 'InitialAccessTactics Rule #258',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1259',
    name: 'InitialAccessTactics Rule #259',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1260',
    name: 'InitialAccessTactics Rule #260',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1261',
    name: 'InitialAccessTactics Rule #261',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1262',
    name: 'InitialAccessTactics Rule #262',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1263',
    name: 'InitialAccessTactics Rule #263',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1264',
    name: 'InitialAccessTactics Rule #264',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1265',
    name: 'InitialAccessTactics Rule #265',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1266',
    name: 'InitialAccessTactics Rule #266',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1267',
    name: 'InitialAccessTactics Rule #267',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1268',
    name: 'InitialAccessTactics Rule #268',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1269',
    name: 'InitialAccessTactics Rule #269',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1270',
    name: 'InitialAccessTactics Rule #270',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1271',
    name: 'InitialAccessTactics Rule #271',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1272',
    name: 'InitialAccessTactics Rule #272',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1273',
    name: 'InitialAccessTactics Rule #273',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1274',
    name: 'InitialAccessTactics Rule #274',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1275',
    name: 'InitialAccessTactics Rule #275',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1276',
    name: 'InitialAccessTactics Rule #276',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1277',
    name: 'InitialAccessTactics Rule #277',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1278',
    name: 'InitialAccessTactics Rule #278',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1279',
    name: 'InitialAccessTactics Rule #279',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1280',
    name: 'InitialAccessTactics Rule #280',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1281',
    name: 'InitialAccessTactics Rule #281',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1282',
    name: 'InitialAccessTactics Rule #282',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1283',
    name: 'InitialAccessTactics Rule #283',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1284',
    name: 'InitialAccessTactics Rule #284',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1285',
    name: 'InitialAccessTactics Rule #285',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1286',
    name: 'InitialAccessTactics Rule #286',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1287',
    name: 'InitialAccessTactics Rule #287',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1288',
    name: 'InitialAccessTactics Rule #288',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1289',
    name: 'InitialAccessTactics Rule #289',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1290',
    name: 'InitialAccessTactics Rule #290',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1291',
    name: 'InitialAccessTactics Rule #291',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1292',
    name: 'InitialAccessTactics Rule #292',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1293',
    name: 'InitialAccessTactics Rule #293',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1294',
    name: 'InitialAccessTactics Rule #294',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1295',
    name: 'InitialAccessTactics Rule #295',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1296',
    name: 'InitialAccessTactics Rule #296',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1297',
    name: 'InitialAccessTactics Rule #297',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1298',
    name: 'InitialAccessTactics Rule #298',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1299',
    name: 'InitialAccessTactics Rule #299',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1300',
    name: 'InitialAccessTactics Rule #300',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1301',
    name: 'InitialAccessTactics Rule #301',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1302',
    name: 'InitialAccessTactics Rule #302',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1303',
    name: 'InitialAccessTactics Rule #303',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1304',
    name: 'InitialAccessTactics Rule #304',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1305',
    name: 'InitialAccessTactics Rule #305',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1306',
    name: 'InitialAccessTactics Rule #306',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1307',
    name: 'InitialAccessTactics Rule #307',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1308',
    name: 'InitialAccessTactics Rule #308',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1309',
    name: 'InitialAccessTactics Rule #309',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1310',
    name: 'InitialAccessTactics Rule #310',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1311',
    name: 'InitialAccessTactics Rule #311',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1312',
    name: 'InitialAccessTactics Rule #312',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1313',
    name: 'InitialAccessTactics Rule #313',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1314',
    name: 'InitialAccessTactics Rule #314',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1315',
    name: 'InitialAccessTactics Rule #315',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1316',
    name: 'InitialAccessTactics Rule #316',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1317',
    name: 'InitialAccessTactics Rule #317',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1318',
    name: 'InitialAccessTactics Rule #318',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1319',
    name: 'InitialAccessTactics Rule #319',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1320',
    name: 'InitialAccessTactics Rule #320',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1321',
    name: 'InitialAccessTactics Rule #321',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1322',
    name: 'InitialAccessTactics Rule #322',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1323',
    name: 'InitialAccessTactics Rule #323',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1324',
    name: 'InitialAccessTactics Rule #324',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1325',
    name: 'InitialAccessTactics Rule #325',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1326',
    name: 'InitialAccessTactics Rule #326',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1327',
    name: 'InitialAccessTactics Rule #327',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1328',
    name: 'InitialAccessTactics Rule #328',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1329',
    name: 'InitialAccessTactics Rule #329',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1330',
    name: 'InitialAccessTactics Rule #330',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1331',
    name: 'InitialAccessTactics Rule #331',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1332',
    name: 'InitialAccessTactics Rule #332',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1333',
    name: 'InitialAccessTactics Rule #333',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1334',
    name: 'InitialAccessTactics Rule #334',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1335',
    name: 'InitialAccessTactics Rule #335',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1336',
    name: 'InitialAccessTactics Rule #336',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1337',
    name: 'InitialAccessTactics Rule #337',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1338',
    name: 'InitialAccessTactics Rule #338',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1339',
    name: 'InitialAccessTactics Rule #339',
    category: 'and drive-by compromise vectors',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1340',
    name: 'InitialAccessTactics Rule #340',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1341',
    name: 'InitialAccessTactics Rule #341',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1342',
    name: 'InitialAccessTactics Rule #342',
    category: 'supply chain compromise',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1343',
    name: 'InitialAccessTactics Rule #343',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1344',
    name: 'InitialAccessTactics Rule #344',
    category: 'Spearphishing attachments',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1345',
    name: 'InitialAccessTactics Rule #345',
    category: 'external remote services',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1346',
    name: 'InitialAccessTactics Rule #346',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1347',
    name: 'InitialAccessTactics Rule #347',
    category: 'and drive-by compromise vectors',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1348',
    name: 'InitialAccessTactics Rule #348',
    category: 'Spearphishing attachments',
    severity: 'CRITICAL',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1349',
    name: 'InitialAccessTactics Rule #349',
    category: 'external remote services',
    severity: 'MEDIUM',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  },
  {
    tacticId: 'TA0001-T1350',
    name: 'InitialAccessTactics Rule #350',
    category: 'supply chain compromise',
    severity: 'HIGH',
    sigmaCondition: 'selection and not filter',
    edrDetectionHook: 'kernel_etw_threat_intel_stream',
    automatedSoarContainment: true
  }
];

export class TA0001_TacticCatalog {
  static search(query: string): MitreTacticSpec[] {
    const q = query.toLowerCase().trim();
    if (!q) return MITRE_TA0001_DATASET.slice(0, 20);
    return MITRE_TA0001_DATASET.filter(t => t.name.toLowerCase().includes(q) || t.tacticId.toLowerCase().includes(q));
  }
}
