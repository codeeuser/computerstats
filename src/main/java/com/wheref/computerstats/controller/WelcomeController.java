package com.wheref.computerstats.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.CentralProcessor.PhysicalProcessor;
import oshi.hardware.CentralProcessor.ProcessorCache;
import oshi.hardware.CentralProcessor.TickType;
import oshi.hardware.ComputerSystem;
import oshi.hardware.Display;
import oshi.hardware.GlobalMemory;
import oshi.hardware.GraphicsCard;
import oshi.hardware.HWDiskStore;
import oshi.hardware.HWPartition;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.LogicalVolumeGroup;
import oshi.hardware.NetworkIF;
import oshi.hardware.PowerSource;
import oshi.hardware.Sensors;
import oshi.hardware.SoundCard;
import oshi.hardware.UsbDevice;
import oshi.hardware.VirtualMemory;
import oshi.software.os.FileSystem;
import oshi.software.os.InternetProtocolStats;
import oshi.software.os.NetworkParams;
import oshi.software.os.OSFileStore;
import oshi.software.os.OSProcess;
import oshi.software.os.OSService;
import oshi.software.os.OSSession;
import oshi.software.os.OperatingSystem;
import oshi.software.os.OperatingSystem.ProcessFiltering;
import oshi.software.os.OperatingSystem.ProcessSorting;
import oshi.util.FormatUtil;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api")
public class WelcomeController {

    enum ITEMS {
        OS,
        CPU,
        SYSTEM,
        MEM,
        SENSOR,
        FILESYSTEM,
        DISK,
        NETWORK,
        PROCESSLIST
    }
    
    @GetMapping("/computer")
	public Map<String, Object> computer() {
        Map<String, Object> root = new LinkedHashMap<>();

        SystemInfo si = new SystemInfo();
        HardwareAbstractionLayer hal = si.getHardware();
        OperatingSystem os = si.getOperatingSystem();
        root.put("OperatingSystem", printOperatingSystem(os));
        root.put("ComputerSystem", printComputerSystem(hal.getComputerSystem()));
        root.put("Processor", printProcessor(hal.getProcessor()));
        root.put("Memory", printMemory(hal.getMemory()));
        root.put("Cpu", printCpu(hal.getProcessor()));
        root.put("Processes", printProcesses(os, hal.getMemory()));
        root.put("Services", printServices(os));
        root.put("Sensors", printSensors(hal.getSensors()));
        root.put("PowerSources", printPowerSources(hal.getPowerSources()));
        root.put("Disks", printDisks(hal.getDiskStores()));
        root.put("LVgroups", printLVgroups(hal.getLogicalVolumeGroups()));
        root.put("FileSystem", printFileSystem(os.getFileSystem()));
        root.put("NetworkInterfaces", printNetworkInterfaces(hal.getNetworkIFs()));
        root.put("NetworkParameters", printNetworkParameters(os.getNetworkParams()));
        root.put("InternetProtocolStats", printInternetProtocolStats(os.getInternetProtocolStats()));
        root.put("Displays", printDisplays(hal.getDisplays()));
        root.put("UsbDevices", printUsbDevices(hal.getUsbDevices(true)));
        root.put("SoundCards", printSoundCards(hal.getSoundCards()));
        root.put("GraphicsCards", printGraphicsCards(hal.getGraphicsCards()));

        return root;
    }

    @GetMapping("/single/{items}")
	public Map<String, Object> single(@PathVariable List<String> items) {
        Map<String, Object> root = new LinkedHashMap<>();
        SystemInfo si = new SystemInfo();
        HardwareAbstractionLayer hal = si.getHardware();
        OperatingSystem os = si.getOperatingSystem();
        if (items.contains(ITEMS.CPU.toString().toLowerCase())){
            root.put("Cpu", printCpu(hal.getProcessor()));
        } 
        if (items.contains(ITEMS.OS.toString().toLowerCase())){
            root.put("OperatingSystem", printOperatingSystem(os));
        }
        if (items.contains(ITEMS.SYSTEM.toString().toLowerCase())){
            root.put("ComputerSystem", printComputerSystem(hal.getComputerSystem()));
        }
        if (items.contains(ITEMS.MEM.toString().toLowerCase())){
            root.put("Memory", printMemory(hal.getMemory()));
        }
        if (items.contains(ITEMS.SENSOR.toString().toLowerCase())){
            root.put("Sensors", printSensors(hal.getSensors()));
        }
        if (items.contains(ITEMS.FILESYSTEM.toString().toLowerCase())){
            root.put("FileSystem", printFileSystem(os.getFileSystem()));
        }
        if (items.contains(ITEMS.DISK.toString().toLowerCase())){
            root.put("Disks", printDisks(hal.getDiskStores()));
        }
        if (items.contains(ITEMS.NETWORK.toString().toLowerCase())){
            root.put("NetworkInterfaces", printNetworkInterfaces(hal.getNetworkIFs()));
            root.put("NetworkParameters", printNetworkParameters(os.getNetworkParams()));
            root.put("InternetProtocolStats", printInternetProtocolStats(os.getInternetProtocolStats()));
        }
        if (items.contains(ITEMS.PROCESSLIST.toString().toLowerCase())){
            root.put("Processes", printProcesses(os, hal.getMemory()));
        }
        return root;
    }

    private static Map<String, Object> printOperatingSystem(final OperatingSystem os) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("os", String.valueOf(os));
        oshi.put("Booted", Instant.ofEpochSecond(os.getSystemBootTime()));
        oshi.put("Uptime", FormatUtil.formatElapsedSecs(os.getSystemUptime()));
        oshi.put("Running with", (os.isElevated() ? "" : "out") + " elevated permissions.");
        for (OSSession s : os.getSessions()) {
            oshi.put("session", s.toString());
        }
        return oshi;
    }

    private static Map<String, Object> printComputerSystem(final ComputerSystem computerSystem) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("System", computerSystem.toString());
        oshi.put("Firmware", computerSystem.getFirmware().toString());
        oshi.put("Baseboard", computerSystem.getBaseboard().toString());
        return oshi;
    }

    private static Map<String, Object> printProcessor(CentralProcessor processor) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("processor", processor.toString());

        Map<Integer, Integer> efficiencyCount = new HashMap<>();
        int maxEfficiency = 0;
        for (PhysicalProcessor cpu : processor.getPhysicalProcessors()) {
            int eff = cpu.getEfficiency();
            efficiencyCount.merge(eff, 1, Integer::sum);
            if (eff > maxEfficiency) {
                maxEfficiency = eff;
            }
        }
        oshi.put("Topology", String.format(Locale.ROOT, "  %7s %4s %4s %4s %4s %4s", "LogProc", "P/E", "Proc", "Pkg", "NUMA",
                "PGrp"));
        for (PhysicalProcessor cpu : processor.getPhysicalProcessors()) {
            oshi.put("processor", String.format(Locale.ROOT, "  %7s %4s %4d %4s %4d %4d",
                    processor.getLogicalProcessors().stream()
                            .filter(p -> p.getPhysicalProcessorNumber() == cpu.getPhysicalProcessorNumber())
                            .filter(p -> p.getPhysicalPackageNumber() == cpu.getPhysicalPackageNumber())
                            .map(p -> Integer.toString(p.getProcessorNumber())).collect(Collectors.joining(",")),
                    cpu.getEfficiency() == maxEfficiency ? "P" : "E", cpu.getPhysicalProcessorNumber(),
                    cpu.getPhysicalPackageNumber(),
                    processor.getLogicalProcessors().stream()
                            .filter(p -> p.getPhysicalProcessorNumber() == cpu.getPhysicalProcessorNumber())
                            .filter(p -> p.getPhysicalPackageNumber() == cpu.getPhysicalPackageNumber())
                            .mapToInt(p -> p.getNumaNode()).findFirst().orElse(0),
                    processor.getLogicalProcessors().stream()
                            .filter(p -> p.getPhysicalProcessorNumber() == cpu.getPhysicalProcessorNumber())
                            .filter(p -> p.getPhysicalPackageNumber() == cpu.getPhysicalPackageNumber())
                            .mapToInt(p -> p.getProcessorGroup()).findFirst().orElse(0)));
        }
        List<ProcessorCache> caches = processor.getProcessorCaches();
        for (int i = 0; i < caches.size(); i++) {
            ProcessorCache cache = caches.get(i);
            boolean perCore = cache.getLevel() < 3;
            boolean pCore = perCore && i < caches.size() - 1 && cache.getLevel() == caches.get(i + 1).getLevel()
                    && cache.getType() == caches.get(i + 1).getType();
            boolean eCore = perCore && i > 0 && cache.getLevel() == caches.get(i - 1).getLevel()
                    && cache.getType() == caches.get(i - 1).getType();
            StringBuilder sb = new StringBuilder("  ").append(cache);
            if (perCore) {
                sb.append(" (per ");
                if (pCore) {
                    sb.append("P-");
                } else if (eCore) {
                    sb.append("E-");
                }
                sb.append("core)");
            }
            oshi.put("cache",sb.toString());
        }
        return oshi;
    }

    private static Map<String, Object> printMemory(GlobalMemory memory) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("Physical Memory", memory.toString());
        oshi.put("Available", memory.getAvailable());
        oshi.put("PageSize", memory.getPageSize());
        oshi.put("Total", memory.getTotal());
        oshi.put("PhysicalMemory", memory.getPhysicalMemory());
        VirtualMemory vm = memory.getVirtualMemory();
        oshi.put("Virtual Memory", vm.toString());
        oshi.put("SwapPagesIn", vm.getSwapPagesIn());
        oshi.put("SwapPagesOut", vm.getSwapPagesOut());
        oshi.put("SwapTotal", vm.getSwapTotal());
        oshi.put("SwapUsed", vm.getSwapUsed());
        oshi.put("VirtualInUse", vm.getVirtualInUse());
        oshi.put("VirtualMax", vm.getVirtualMax());
        return oshi;
    }

    private static Map<String, Object> printCpu(CentralProcessor processor) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("Context Switches/Interrupts: ", processor.getContextSwitches() + " / " + processor.getInterrupts());

        long[] prevTicks = processor.getSystemCpuLoadTicks();
        long[][] prevProcTicks = processor.getProcessorCpuLoadTicks();
        oshi.put("CPU, IOWait, and IRQ ticks @ 0 sec", prevTicks);
        // Wait a second...
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.interrupted();
        }
        long[] ticks = processor.getSystemCpuLoadTicks();
        oshi.put("CPU, IOWait, and IRQ ticks @ 1 sec", ticks);
        long user = ticks[TickType.USER.getIndex()] - prevTicks[TickType.USER.getIndex()];
        long nice = ticks[TickType.NICE.getIndex()] - prevTicks[TickType.NICE.getIndex()];
        long sys = ticks[TickType.SYSTEM.getIndex()] - prevTicks[TickType.SYSTEM.getIndex()];
        long idle = ticks[TickType.IDLE.getIndex()] - prevTicks[TickType.IDLE.getIndex()];
        long iowait = ticks[TickType.IOWAIT.getIndex()] - prevTicks[TickType.IOWAIT.getIndex()];
        long irq = ticks[TickType.IRQ.getIndex()] - prevTicks[TickType.IRQ.getIndex()];
        long softirq = ticks[TickType.SOFTIRQ.getIndex()] - prevTicks[TickType.SOFTIRQ.getIndex()];
        long steal = ticks[TickType.STEAL.getIndex()] - prevTicks[TickType.STEAL.getIndex()];
        long totalCpu = user + nice + sys + idle + iowait + irq + softirq + steal;

        oshi.put("user", user);
        oshi.put("nice", nice);
        oshi.put("sys", sys);
        oshi.put("idle", idle);
        oshi.put("iowait", iowait);
        oshi.put("irq", irq);
        oshi.put("softirq", softirq);
        oshi.put("steal", steal);
        oshi.put("totalCpu", totalCpu);

        oshi.put("Info", String.format(Locale.ROOT,
                "User: %.1f%% Nice: %.1f%% System: %.1f%% Idle: %.1f%% IOwait: %.1f%% IRQ: %.1f%% SoftIRQ: %.1f%% Steal: %.1f%%",
                100d * user / totalCpu, 100d * nice / totalCpu, 100d * sys / totalCpu, 100d * idle / totalCpu,
                100d * iowait / totalCpu, 100d * irq / totalCpu, 100d * softirq / totalCpu, 100d * steal / totalCpu));
        oshi.put("System Cpu Load Between Ticks", processor.getSystemCpuLoadBetweenTicks(prevTicks) * 100);
        double[] loadAverage = processor.getSystemLoadAverage(3);
        oshi.put("CPU load averages", loadAverage);
        double[] load = processor.getProcessorCpuLoadBetweenTicks(prevProcTicks);
        oshi.put("cpucore", load.length);
        int count = 1;
        for (double avg : load) {
            oshi.put("CPU "+ (count++) +" load per processor", avg * 100);
        }
        
        long freq = processor.getProcessorIdentifier().getVendorFreq();
        if (freq > 0) {
            oshi.put("Vendor Frequency", FormatUtil.formatHertz(freq));
        }
        freq = processor.getMaxFreq();
        if (freq > 0) {
            oshi.put("Max Frequency", FormatUtil.formatHertz(freq));
        }
        long[] freqs = processor.getCurrentFreq();
        if (freqs[0] > 0) {
            for (int i = 0; i < freqs.length; i++) {
                oshi.put("Current Freq", FormatUtil.formatHertz(freqs[i]));
            }
        }
        if (!processor.getFeatureFlags().isEmpty()) {
            for (String features : processor.getFeatureFlags()) {
                oshi.put("Feature Flag", features);
            }
        }
        return oshi;
    }

    private static Map<String, Object> printProcesses(OperatingSystem os, GlobalMemory memory) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        OSProcess myProc = os.getProcess(os.getProcessId());
        // current process will never be null. Other code should check for null here
        oshi.put("My PID", myProc.getProcessID() + " with affinity " + Long.toBinaryString(myProc.getAffinityMask()));
        oshi.put("My TID", os.getThreadId() + " with details " + os.getCurrentThread());

        oshi.put("Process Count", os.getProcessCount());
        oshi.put("Thread Count", os.getThreadCount());
        // Sort by highest CPU
        List<Map<String, Object>> list = new LinkedList<>();
        List<OSProcess> procs = os.getProcesses(ProcessFiltering.ALL_PROCESSES, ProcessSorting.CPU_DESC, 5);
        for (int i = 0; i < procs.size(); i++) {
            OSProcess p = procs.get(i);
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("PID", p.getProcessID());
            map.put("%CPU", 100d * (p.getKernelTime() + p.getUserTime()) / p.getUpTime());
            map.put("%MEM", 100d * p.getResidentSetSize() / memory.getTotal());
            map.put("VSZ", FormatUtil.formatBytes(p.getVirtualSize()));
            map.put("RSS", FormatUtil.formatBytes(p.getResidentSetSize()));
            map.put("Name", p.getName());
            list.add(map);
        }
        oshi.put("ProcesseList", list);
        OSProcess p = os.getProcess(os.getProcessId());
        for (String s : p.getArguments()) {
            oshi.put("Current Process Arguments", s);
        }
        for (Entry<String, String> e : p.getEnvironmentVariables().entrySet()) {
            oshi.put("Current Process Environment", e);
        }
        return oshi;
    }

    private static Map<String, Object> printServices(OperatingSystem os) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        // DO 5 each of running and stopped
        List<Map<String, Object>> runningList = new LinkedList<>();
        List<Map<String, Object>> stoppedList = new LinkedList<>();
        int i = 0;
        for (OSService s : os.getServices()) {
            Map<String, Object> map = new LinkedHashMap<>();
            if (s.getState().equals(OSService.State.RUNNING) && i++ < 5) {
                map.put("PID", s.getProcessID());
                map.put("State", s.getState());
                map.put("Name", s.getName());
                runningList.add(map);
            }
        }
        i = 0;
        for (OSService s : os.getServices()) {
            Map<String, Object> map = new LinkedHashMap<>();
            if (s.getState().equals(OSService.State.STOPPED) && i++ < 5) {
                map.put("PID", s.getProcessID());
                map.put("State", s.getState());
                map.put("Name", s.getName());
                stoppedList.add(map);
            }
        }
        oshi.put("Running Processes", runningList);
        oshi.put("Stopped Processes", stoppedList);
        return oshi;
    }

    private static Map<String, Object> printSensors(Sensors sensors) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("Sensor List", sensors);
        return oshi;
    }

    private static Map<String, Object> printPowerSources(List<PowerSource> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        for (PowerSource powerSource : list) {
            oshi.put("Power Source", powerSource);
        }        
        return oshi;
    }

    private static Map<String, Object> printDisks(List<HWDiskStore> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        for (HWDiskStore disk : list) {
            oshi.put("Disk", disk);

            List<HWPartition> partitions = disk.getPartitions();
            for (HWPartition part : partitions) {
                oshi.put("Partition", part);
            }
        }
        return oshi;
    }

    private static Map<String, Object> printLVgroups(List<LogicalVolumeGroup> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        if (!list.isEmpty()) {
            for (LogicalVolumeGroup lvg : list) {
                oshi.put("Logical Volume Groups", lvg);
            }
        }
        return oshi;
    }

    private static Map<String, Object> printFileSystem(FileSystem fileSystem) {
        Map<String, Object> oshi = new LinkedHashMap<>();

        oshi.put("Open File Descriptors", fileSystem.getOpenFileDescriptors());
        oshi.put("Max File Descriptors", fileSystem.getMaxFileDescriptors());

        for (OSFileStore fs : fileSystem.getFileStores()) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("Usable Space", fs.getUsableSpace());
            map.put("Total Space", fs.getTotalSpace());
            map.put("Name", fs.getName());
            map.put("Description", fs.getDescription());
            map.put("Type", fs.getType());
            map.put("Free Inodes", fs.getFreeInodes());
            map.put("Total Inodes", fs.getTotalInodes());
            map.put("Volume", fs.getVolume());
            map.put("Logical Volume", fs.getLogicalVolume());
            map.put("Mount", fs.getMount());
        }
        return oshi;
    }

    private static Map<String, Object> printNetworkInterfaces(List<NetworkIF> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        for (NetworkIF net : list) {
            oshi.put("Network Interface List", net);
        }
        
        return oshi;
    }

    private static Map<String, Object> printNetworkParameters(NetworkParams networkParams) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("Network parameters", networkParams);
        return oshi;
    }

    private static Map<String, Object> printInternetProtocolStats(InternetProtocolStats ip) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        oshi.put("TCPv4", ip.getTCPv4Stats());
        oshi.put("TCPv6", ip.getTCPv6Stats());
        oshi.put("UDPv4", ip.getUDPv4Stats());
        oshi.put("UDPv6", ip.getUDPv6Stats());
        return oshi;
    }

    private static Map<String, Object> printDisplays(List<Display> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        int count = 1;
        for (Display display : list) {
            oshi.put("Display " + (count++), display);
        }
        return oshi;
    }

    private static Map<String, Object> printUsbDevices(List<UsbDevice> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        for (UsbDevice usbDevice : list) {
            oshi.put("Usb Device List", usbDevice);
        }
        return oshi;
    }

    private static Map<String, Object> printSoundCards(List<SoundCard> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        for (SoundCard card : list) {
            oshi.put("Sound Card List", card);
        }
        return oshi;
    }

    private static Map<String, Object> printGraphicsCards(List<GraphicsCard> list) {
        Map<String, Object> oshi = new LinkedHashMap<>();
        for (GraphicsCard card : list) {
            oshi.put("Graphics Card List", card);
        }
        return oshi;
    }
}
