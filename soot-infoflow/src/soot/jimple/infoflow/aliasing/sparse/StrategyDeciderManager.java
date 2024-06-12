package soot.jimple.infoflow.aliasing.sparse;

import boomerang.BackwardQuery;
import boomerang.Boomerang;
import boomerang.DefaultBoomerangOptions;
import boomerang.datacollection.DataCollection;
import boomerang.datacollection.MethodLog;
import boomerang.datacollection.QueryLog;
import boomerang.results.BackwardBoomerangResults;
import boomerang.scene.*;
import boomerang.scene.jimple.*;
import boomerang.scene.sparse.SparseCFGCache;
import boomerang.util.AccessPath;
import com.google.common.base.Stopwatch;
import org.jpmml.evaluator.Evaluator;
import org.jpmml.evaluator.LoadingModelEvaluatorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.Stmt;
import wpds.impl.Weight;

import javax.annotation.Nullable;
import java.io.File;
import java.time.Duration;
import java.util.*;

public class StrategyDeciderManager {

    private static Logger LOGGER = LoggerFactory.getLogger(StrategyDeciderManager.class);

    private static StrategyDeciderManager INSTANCE;

    private Boomerang boomerangSolver;

    private SootCallGraph sootCallGraph;
    private DataFlowScope dataFlowScope;

    private SparseCFGCache.SparsificationStrategy sparsificationStrategy;

    private int queryCount = 0;
    private DataCollection dataCollection;
    private Map<Integer, BackwardQuery> id2Query = new HashMap<>();
    private Map<Integer, Long> id2PDSBuildingTime = new HashMap();
    private Map<Integer, Long> id2AliasSearchingTime = new HashMap();
    private Map<Integer, Long> id2QueryTime = new HashMap();
    private static Duration evaluatorBuildingDuration = Duration.ZERO;
    private Duration totalAliasingDuration;
    private Evaluator evaluator;

    static class FlowDroidBoomerangOptions extends DefaultBoomerangOptions {

        private SparseCFGCache.SparsificationStrategy sparsificationStrategy;
        private Evaluator evaluator = null;

        public FlowDroidBoomerangOptions(SparseCFGCache.SparsificationStrategy sparsificationStrategy, Evaluator evaluator){
            this.sparsificationStrategy = sparsificationStrategy;
            this.evaluator = evaluator;
        }

        @Override
        public SparseCFGCache.SparsificationStrategy getSparsificationStrategy() {
            if(this.sparsificationStrategy==null){
                return SparseCFGCache.SparsificationStrategy.NONE;
            }
            return this.sparsificationStrategy;
        }

        @Override
        public int analysisTimeoutMS() {
            return Integer.MAX_VALUE;
        }

        @Override
        public boolean onTheFlyCallGraph() {
            return false;
        }

        @Override
        public StaticFieldStrategy getStaticFieldStrategy() {
            return StaticFieldStrategy.FLOW_SENSITIVE;
        }

        @Override
        public boolean allowMultipleQueries() {
            return true;
        }

        @Override
        public boolean throwFlows() {
            return true;
        }

        @Override
        public boolean trackAnySubclassOfThrowable() {
            return true;
        }

        @Override
        public boolean handleSpecialInvokeAsNormalPropagation() {
            return true;
        }

        @Override
        @Nullable
        public Evaluator getEvaluator() {
            return this.evaluator;
        }
    }

    private StrategyDeciderManager(SparseCFGCache.SparsificationStrategy sparsificationStrategy) {
        System.out.println("I'm here");
        this.sparsificationStrategy = sparsificationStrategy;
        if (sparsificationStrategy == SparseCFGCache.SparsificationStrategy.DYNAMIC) {
            Stopwatch stopwatch = Stopwatch.createStarted();
            File pmml = new File("pmml/strategy_decider.pmml");
            try {
                evaluator = new LoadingModelEvaluatorBuilder().load(pmml).build();
                evaluatorBuildingDuration = stopwatch.stop().elapsed();
                System.out.println(evaluatorBuildingDuration.toNanos());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        totalAliasingDuration = Duration.ZERO;
        sootCallGraph = new SootCallGraph();
        dataFlowScope = SootDataFlowScope.make(Scene.v());
        dataCollection = DataCollection.getInstance();
    }

    public static Duration getEvaluatorBuildingDuration() {
        return evaluatorBuildingDuration;
    }
    public Duration getTotalDuration() {
        return totalAliasingDuration;
    }

    public static synchronized StrategyDeciderManager getInstance(SparseCFGCache.SparsificationStrategy sparsificationStrategy) {
        if (INSTANCE == null || INSTANCE.sparsificationStrategy!=sparsificationStrategy) {
            INSTANCE = new StrategyDeciderManager(sparsificationStrategy);
        }
        return INSTANCE;
    }

    /**
     * @param stmt   Statement that contains the value. E.g. Value can be the leftOp
     * @param method Method that contains the Stmt
     * @param value  We actually want to find this local's aliases
     * @return
     */
    public synchronized Set<AccessPath> getAliases(Stmt stmt, SootMethod method, Value value) {
        BackwardQuery query = createQuery(stmt, method, value);
        Stopwatch stopwatch = Stopwatch.createStarted();
        Set<AccessPath> aliases = getAliases(query);
        Duration elapsed = stopwatch.elapsed();
        this.id2QueryTime.put(queryCount-1, elapsed.toNanos());
        totalAliasingDuration = totalAliasingDuration.plus(elapsed);
        return aliases;
    }

    private QueryLog countQuery(BackwardQuery query) {
        id2Query.put(queryCount, query);
        QueryLog queryLog = dataCollection.registerQuery(queryCount, query);
        queryCount++;
        return queryLog;
    }

    public int getQueryCount(){
        return queryCount;
    }

    private BackwardQuery createQuery(Stmt stmt, SootMethod method, Value value) {
            JimpleMethod jimpleMethod = JimpleMethod.of(method);
            Statement statement = JimpleStatement.create(stmt, jimpleMethod);
            JimpleVal val = new JimpleVal(value, jimpleMethod);
            Optional<Statement> first = statement.getMethod().getControlFlowGraph().getSuccsOf(statement).stream().findFirst();
            if(first.isPresent()){
                return BackwardQuery.make(new ControlFlowGraph.Edge(statement, first.get()), val);
            }
            throw new RuntimeException("No successors for: " + statement);
    }

    private Set<AccessPath> getAliases(BackwardQuery query){
        QueryLog queryLog = countQuery(query);
        boomerangSolver =
                new Boomerang(
                        sootCallGraph, dataFlowScope, new FlowDroidBoomerangOptions(INSTANCE.sparsificationStrategy, evaluator));

        // record PDS building time
        Stopwatch stopwatch = Stopwatch.createUnstarted();
        stopwatch.start();
        BackwardBoomerangResults<Weight.NoWeight> results = boomerangSolver.solve(query);
        stopwatch.stop();
        Duration elapsed = stopwatch.elapsed();
        this.id2PDSBuildingTime.put(queryCount - 1, elapsed.toNanos());

        Stopwatch stopwatch2 = Stopwatch.createUnstarted();
        stopwatch2.start();
        Set<AccessPath> aliases = results.getAllAliases();
        stopwatch2.stop();
        elapsed = stopwatch2.elapsed();
        this.id2AliasSearchingTime.put(queryCount - 1, elapsed.toNanos());

        if (sparsificationStrategy == SparseCFGCache.SparsificationStrategy.DYNAMIC) {
            queryLog.storeSCFGLogs(
                    SparseCFGCache.getInstance(
                                    SparseCFGCache.SparsificationStrategy.TYPE_BASED, true)
                            .getSCFGLogs());
            queryLog.storeSCFGLogs(
                    SparseCFGCache.getInstance(
                                    SparseCFGCache.SparsificationStrategy.ALIAS_AWARE, true)
                            .getSCFGLogs());
            SparseCFGCache.getInstance(SparseCFGCache.SparsificationStrategy.TYPE_BASED, true)
                    .resetSCFGLogs();
            SparseCFGCache.getInstance(
                            SparseCFGCache.SparsificationStrategy.ALIAS_AWARE, true)
                    .resetSCFGLogs();

        } else if (sparsificationStrategy != SparseCFGCache.SparsificationStrategy.NONE) {
            queryLog.storeSCFGLogs(
                    SparseCFGCache.getInstance(sparsificationStrategy, true).getSCFGLogs());
            SparseCFGCache.getInstance(sparsificationStrategy, true).resetSCFGLogs();
        }
        return aliases;
    }

    private void resultsPrinter() {
        for (int i = 0; i < queryCount; i++) {
            BackwardQuery query = this.id2Query.get(i);
            LOGGER.info(query.getInfo());
            LOGGER.info(
                    "QueryTime: {}  PDSBuildingTime: {}  AliasSearchingTime: {}",
                    this.id2QueryTime.get(i),
                    this.id2PDSBuildingTime.get(i),
                    this.id2AliasSearchingTime.get(i));
            QueryLog queryLog = dataCollection.getQueryLog(i);
            for (MethodLog methodLog : queryLog.getMethodLogs()) {
                LOGGER.info(methodLog.toString());
            }
        }
        LOGGER.info("Running Time: {}", totalAliasingDuration.toMillis());
    }

    public Map<Integer, BackwardQuery> getId2Query() {
        return id2Query;
    }

    public Map<Integer, Long> getId2PDSBuildingTime() {
        return id2PDSBuildingTime;
    }

    public Map<Integer, Long> getId2AliasSearchingTime() {
        return id2AliasSearchingTime;
    }

    public Map<Integer, Long> getId2QueryTime() {
        return id2QueryTime;
    }
}
