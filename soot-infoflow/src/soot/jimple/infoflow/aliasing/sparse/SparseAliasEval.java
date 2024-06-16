package soot.jimple.infoflow.aliasing.sparse;

import boomerang.datacollection.DataCollection;
import boomerang.datacollection.DecisionLog;
import boomerang.datacollection.QueryLog;
import boomerang.scene.sparse.SparseCFGCache;
import boomerang.scene.sparse.eval.SparseCFGQueryLog;
import soot.jimple.infoflow.results.InfoflowPerformanceData;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * to create evaluation data
 * targetProgram, sparse mode, sparseCFG build time, #cache hit, #cache miss, total query time, #total propagation
 */
public class SparseAliasEval {

    private static final String OUT_PUT_DIR = "./apk_raw_result";
    private static final String FILE = "alias_eval.csv";
    private static String targetProgram;

    private final SparseCFGCache.SparsificationStrategy sparsificationStrategy;
    private long pdsBuildingTime=0;
    private long aliasingSearchingTime = 0;
    private long evaluatorBuildingTime = 0;
    private long decisionTime = 0;
    private long queryCount = 0;
    private long sparseCFGBuildTime=0;// issued by the client
    private long scfgBuildCount = 0; // client queries + internal queries that lead to SCFG construction, i.e. not retrieved from cache
    private InfoflowPerformanceData performanceData;
    private float initialStmtCount = 0;
    private float finalStmtCount = 0;

    public SparseAliasEval(SparseCFGCache.SparsificationStrategy sparsificationStrategy, InfoflowPerformanceData performanceData) {
        this.sparsificationStrategy = sparsificationStrategy;
        this.performanceData = performanceData;
        handleSparsificationSpecificData();
    }

    public static void setTargetProgram(String apkname){
        targetProgram = apkname;
    }

    private void handleSparsificationSpecificData(){
        queryCount = StrategyDeciderManager.getInstance(sparsificationStrategy).getQueryCount();
        Map<Integer, Long> id2PDSBuildingTime = StrategyDeciderManager.getInstance(sparsificationStrategy).getId2PDSBuildingTime();
        Map<Integer, Long> id2AliasSearchingTime = StrategyDeciderManager.getInstance(sparsificationStrategy).getId2AliasSearchingTime();
        evaluatorBuildingTime = StrategyDeciderManager.getInstance(sparsificationStrategy).getEvaluatorBuildingDuration().toNanos();
        for(int i = 0; i < queryCount; i++ ){
            pdsBuildingTime += id2PDSBuildingTime.get(i);
            aliasingSearchingTime += id2AliasSearchingTime.get(i);
            QueryLog queryLog = DataCollection.getInstance().getQueryLog(i);
            List<SparseCFGQueryLog> scfgLogs = queryLog.getSCFGLogs();
            List<DecisionLog> decisionLogs = queryLog.getDecisionLogs();
            for (SparseCFGQueryLog scfgLog : scfgLogs) {
                sparseCFGBuildTime += scfgLog.getDuration().toNanos();
                if(scfgLog.getInitialStmtCount()>0 && scfgLog.getFinalStmtCount()>0){
                    initialStmtCount += scfgLog.getInitialStmtCount();
                    finalStmtCount += scfgLog.getFinalStmtCount();
                    scfgBuildCount++;
                }
            }
            for (DecisionLog decisionLog : decisionLogs){
                decisionTime += decisionLog.getDuration().toNanos();
            }
        }
    }

    public void generate() {
        File dir = new File(OUT_PUT_DIR);
        if (!dir.exists()) {
            dir.mkdir();
        }
        File file = new File(OUT_PUT_DIR + File.separator + FILE);
        if(!file.exists()){
            try (FileWriter writer = new FileWriter(file)) {
                StringBuilder str = new StringBuilder();
                str.append("apk");
                str.append(",");
                str.append("strategy");
                str.append(",");
                str.append("PDSBuildingTime");
                str.append(",");
                str.append("SCFGBuildingTime");
                str.append(",");
                str.append("aliasesSearchingTime");
                str.append(",");
                str.append("evaluatorBuildingTime");
                str.append(",");
                str.append("decisionTime");
                str.append(",");
                str.append("runtime");
                str.append(",");
                str.append("memoryCost");
                str.append(",");
                str.append("queryCount");
                str.append(",");
                str.append("degreeOfSparse");
                str.append(",");
                str.append("sourceCount");
                str.append(",");
                str.append("SCFGCount");
                str.append(System.lineSeparator());
                writer.write(str.toString());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try (FileWriter writer = new FileWriter(file, true)) {
            StringBuilder str = new StringBuilder();
            str.append(targetProgram);
            str.append(",");
            str.append(sparsificationStrategy);
            str.append(",");
            str.append(pdsBuildingTime);
            str.append(",");
            str.append(sparseCFGBuildTime);
            str.append(",");
            str.append(aliasingSearchingTime);
            str.append(",");
            str.append(evaluatorBuildingTime);
            str.append(",");
            str.append(decisionTime);
            str.append(",");
            str.append(performanceData.getTotalRuntimeSeconds());
            str.append(",");
            str.append(performanceData.getMaxMemoryConsumption());
            str.append(",");
            str.append(queryCount);
            str.append(",");
            str.append(degreeOfSparsification());
            str.append(",");
            str.append(performanceData.getSourceCount());
            str.append(",");
            str.append(scfgBuildCount);
            str.append(System.lineSeparator());
            writer.write(str.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String degreeOfSparsification(){
        if(finalStmtCount!=0){
            return String.format("%.2f",(initialStmtCount -finalStmtCount)/ initialStmtCount);
        }
        return "0";
    }

}
