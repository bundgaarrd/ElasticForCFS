import json
import socket
import struct
from datetime import datetime, timezone

#===============================================
# Functions for parsing primary/secondary header
#===============================================
def parse_primary(data):
    MID = struct.unpack(">H", data[:2])[0] #Extracts the first 2 bytes
    sequnece_count = struct.unpack(">H", data[2:4])[0] & 0x3FFF #Extracts the next 2 bytes
    return {
        "MID": MID,
        "sequnece_count": sequnece_count
    }

def parse_second(data):
    seconds, subseconds = struct.unpack(">IH", data[6:12])
    return {
        "seconds": seconds,
        "subseconds": subseconds
    }

#===============================================
# #Dictionary that maps MsgId to it's payload format
#===============================================
packets = {
    #CFE_EVS housekeeping packets
    0x0801: ("CFE_EVS_HK", "<BBBBBBBBHHBBBB" + "IHBB" * 16, [
        "CommandCounter", "CommandErrorCounter", "MessageFormatMode",
        "MessageTruncCounter", "UnregisteredAppCounter", "OutputPort",
        "LogFullFlag", "LogMode", "MessageSendCounter", "LogOverflowCounter",
        "LogEnabled", "Spare1", "Spare2", "Spare3"] + [
        name for i in range(16) for name in (
            f"AppData{i}_AppID",
            f"AppData{i}_AppMessageSentCounter",
            f"AppData{i}_AppEnableStatus",
            f"AppData{i}_AppMessageSquelchedCounter",
        )]), #Creates the names for the 16 apps in the packet, so each value knows what it is called when we store it"
             # For example, one app is CFE_ES 

    #CFE_SB housekeeping packets
    0x0803: ("CFE_SB_HK", "<BBBBBBBBBBBBHHIII", [
        "CommandCounter", "CommandErrorCounter", "NoSubscribersCounter",
        "MsgSendErrorCounter", "MsgReceiveErrorCounter", "InternalErrorCounter",
        "CreatePipeErrorCounter", "SubscribeErrorCounter",
        "PipeOptsErrorCounter", "DuplicateSubscriptionsCounter",
        "GetPipeIdByNameErrorCounter", "Spare2Align",
        "PipeOverflowErrorCounter", "MsgLimitErrorCounter",
        "MemPoolHandle", "MemInUse", "UnmarkedMem"]),
 
    #CFE_TIME housekeeping packets
    0x0805: ("CFE_TIME_HK", "<BBHhhIIIIII", [
        "CommandCounter", "CommandErrorCounter", "ClockStateFlags",
        "ClockStateAPI", "LeapSeconds", "SecondsMET", "SubsecsMET",
        "SecondsSTCF", "SubsecsSTCF", "Seconds1HzAdj", "Subsecs1HzAdj"]),

    #CFE_ES housekeeping packets
    0x0800: ("CFE_ES_HK", "<BBH" + "B" * 12 + "QQ" + "I" * 28 + "QQQ", [
        "CommandCounter", "CommandErrorCounter", "CFECoreChecksum",
        "CFEMajorVersion", "CFEMinorVersion", "CFERevision", "CFEMissionRevision",
        "OSALMajorVersion", "OSALMinorVersion", "OSALRevision", "OSALMissionRevision",
        "PSPMajorVersion", "PSPMinorVersion", "PSPRevision", "PSPMissionRevision",
        "SysLogBytesUsed", "SysLogSize", "SysLogEntries", "SysLogMode",
        "ERLogIndex", "ERLogEntries",
        "RegisteredCoreApps", "RegisteredExternalApps",
        "RegisteredTasks", "RegisteredLibs",
        "ResetType", "ResetSubtype", "ProcessorResets", "MaxProcessorResets",
        "BootSource", "PerfState", "PerfMode", "PerfTriggerCount",
        "PerfFilterMask0", "PerfFilterMask1", "PerfFilterMask2", "PerfFilterMask3",
        "PerfTriggerMask0", "PerfTriggerMask1", "PerfTriggerMask2", "PerfTriggerMask3",
        "PerfDataStart", "PerfDataEnd", "PerfDataCount", "PerfDataToWrite",
        "HeapBytesFree", "HeapBlocksFree", "HeapMaxBlockSize"]),

    #CFE_TBL housekeeping packets
    0x0804: ("CFE_TBL_HK", "<BBHHHIi?40sBBBBB2xIII40s64s64s40s", [
        "CommandCounter", "CommandErrorCounter", "NumTables", "NumLoadPending",
        "ValidationCounter", "LastValCrc", "LastValStatus", "ActiveBuffer",
        "LastValTableName",
        "SuccessValCounter", "FailedValCounter", "NumValRequests",
        "NumFreeSharedBufs", "ByteAlignPad1",
        "MemPoolHandle",
        "LastUpdateTimeSeconds", "LastUpdateTimeSubseconds",
        "LastUpdatedTable", "LastFileLoaded", "LastFileDumped", "LastTableLoaded"])
}

#===============================================
# Decoder
#===============================================
def decode(data):
    time = datetime.now(timezone.utc).isoformat()
    primary_header = parse_primary(data)
    
    data_dict = primary_header | parse_second(data) # Adds the headers to the data
    data_dict["Timestamp"] = time

    MID = primary_header["MID"] #Extracts MID from the primary header

    housekeeping_name, payload_format, payload_metrics = packets[MID] #Extracts info depending on MID

    payload_bytes = data[16:] #Payload starts from the 16th byte since it is only telemetry data and no commands, yet
    #print(f"MID=0x{MID:04X}, total={len(data)}, payload={len(data[16:])}, expected={struct.calcsize(payload_format)}") #Debug
    values = struct.unpack(payload_format, payload_bytes) #Converts bytes depending on the payload format
    
    payload_dict = {} # Creates a dict to be able to hold the payload values

    for i in range(len(payload_metrics)): #Loops over all payload metrics
        if type(values[i]) == bytes: # If e.g. 40s is in the format it means struct turns it into bytes and you cannot dump bytes in json
            payload_dict[payload_metrics[i]] = values[i].split(b'\x00', 1)[0].decode('ascii') # Removes the padding and converts bytes to a string
        else:
            payload_dict[payload_metrics[i]] = values[i] #Combines metric and value
        

    data_dict = data_dict | payload_dict # Merges all dicts
    data_dict["MID"] = f"0x{MID:04X}" #Converts MID decimal to hex so it matches the MID we know
    data_dict["name"] = housekeeping_name #Adds the name key

    return data_dict


#===============================================
# Main loop
#===============================================
if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 2234))
    print("listening on port 2234. Printing to telemetry.json")

 
    with open("telemetry_dashboard.json", "a", buffering=1) as f: 
        while True:
            data, _ = sock.recvfrom(65535)
            packet = decode(data)
            print(f"Modtaget pakke {packet["MID"]}")
            f.write(json.dumps(packet) + "\n")