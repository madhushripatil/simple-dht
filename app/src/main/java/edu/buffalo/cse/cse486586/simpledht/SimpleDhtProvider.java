package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";
    static final String TAG = SimpleDhtProvider.class.getSimpleName();

    private static final ArrayList<String> remotePorts = new ArrayList<String>();

    private int thisAvdPort;
    private String myPort;
    private int predecessor;
    private int successor;

    final int SERVER_PORT = 10000;
    final int AVD0_PORT = 11108;
    final String SCHEME = "content";
    final String AUTHORITY = "edu.buffalo.cse.cse486586.simpledht.provider";

    String returnResultToQueryInitiator;
    Map<String, String> queryAllResultMap = new LinkedHashMap<String, String>();

    private class RingNode {

        int nodeId;
        int predecessor;
        int successor;

        void setNodeId(int n) {
            nodeId = n;
        }

        void setPredecessor(int p) {
            predecessor = p;
        }

        void setSuccessor(int s) {
            successor = s;
        }

        int getNodeId() {
            return nodeId;
        }

        int getPredecessor() {
            return predecessor;
        }

        int getSuccessor() {
            return successor;
        }
    }

    Map<String, RingNode> avdMap = new TreeMap<String, RingNode>();
    List<Integer> nodeIndexArray = new ArrayList<Integer>();
    List<String> nodeIndexHash = new ArrayList<String>();

    public SimpleDhtProvider() {
        remotePorts.add("11108");
        remotePorts.add("11112");
        remotePorts.add("11116");
        remotePorts.add("11120");
        remotePorts.add("11124");
    }

    private boolean keyBelongsToMe(String filename, int id, int p) {

        Log.i("KEY BELONGS METHOD for ", thisAvdPort * 2 + "");

        Log.i("ACTUAL KEY ", filename);
        Log.i("ACTUAL node ID ", id * 2 + "");
        Log.i("ACTUAL Predecessor ", p * 2 + "");
        Log.i("ACTUAL Successor ", successor + "");

        try {
            String key = genHash(filename);
            String own = genHash(String.valueOf(id));
            String pred = genHash(String.valueOf(p));

            Log.i("HASH KEY ", key);
            Log.i("HASH node ID ", own + "");
            Log.i("HASH Predecessor ", pred + "");

            if (key.compareTo(pred) > 0 && key.compareTo(own) <= 0 && own.compareTo(pred) > 0) {
                Log.e("BELONGS HERE ", "");
                return true;

            } else if (key.compareTo(pred) > 0 && key.compareTo(own) > 0 && own.compareTo(pred) < 0) {
                Log.e("BELONGS HERE ", "");
                return true;

            } else if (key.compareTo(pred) < 0 && key.compareTo(own) <= 0 && own.compareTo(pred) < 0) {
                Log.e("BELONGS HERE ", "");
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("MULTIPLE DEVICE INSERT ", "Error inserting when multiple devices in ring!");
        }
        Log.e("DOESN'T BELONG HERE ", "Pass to  " + successor);
        return false;
    }

    private void writeToFile(String filename, String val) {
        FileOutputStream os;
        Log.e("WRITE TO FILE ", filename);
        try {
            Log.e("HASH KEY ", genHash(filename));
            os = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
            os.write(val.getBytes());
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, "File write failed");
        }
    }

    private void readDataFromDevice(File file, Map<String, String> keyValMap) {
        try {
            Log.e("FILE NAME ", file.getName() + " on device " + thisAvdPort*2);

            InputStreamReader isrd = new InputStreamReader(new FileInputStream(file));
            BufferedReader bufferedReader = new BufferedReader(isrd);
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                keyValMap.put(file.getName(), line);
            }
            bufferedReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readDataFromDevice(File[] files, Map<String, String> keyValMap) {

        Log.e("READ DATA METHOD ", thisAvdPort * 2 + "");

        try {
            for (File file : files) {
                readDataFromDevice(file, keyValMap);
            }
            Log.e("MAP AFTER READING ALL ", thisAvdPort*2+"");
            Log.e("MAP AFTER READING ALL ", keyValMap.toString());
            for(Map.Entry e: keyValMap.entrySet()) {
                Log.e("KEY: " + e.getKey() + "VAL: " + e.getValue().toString(), "");
            }
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("ERROR QUERYING ", "");
        }
    }

    private Cursor getCursorFromMap(Map<String, String> inputMap) {
        Cursor matrixCursor = new MatrixCursor(new String[]{KEY_FIELD, VALUE_FIELD});
        Object[] mRow = new Object[2];
        if (inputMap.size() > 0) {
            for (Map.Entry<String, String> entries : inputMap.entrySet()) {
                mRow[0] = entries.getKey();
                mRow[1] = entries.getValue();
                ((MatrixCursor) matrixCursor).addRow(mRow);
            }
        }
        return matrixCursor;
    }

    private Map getMapFromString(String s) {
        Map<String, String> map = new LinkedHashMap<String, String>();

        if(!s.equals("{}")) {
            s = s.substring(1,s.length()-1);
            String[] pairs = s.split(", ");
            Log.e("PAIRS ",pairs.length + " " + thisAvdPort*2);

            for (int i = 0; i < pairs.length; i++) {
                String pair = pairs[i];
                String[] keyValue = pair.split("=");
                Log.e("PAIR VALUE ", pair);
                map.put(keyValue[0], keyValue[1]);
            }
            Log.e("BUILDING PARTIAL MAP ","current device "+ thisAvdPort*2);
            for(Map.Entry e:map.entrySet()) {
                Log.i("BUILDMAP ","KEY: " + e.getKey() + "  VAL: " + e.getValue());
            }
        }
        return map;
    }

    private void writeToOutPutStream(String data, int port) {
        try {
            Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                    port);
            DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
            outStream.writeUTF(data);
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("WRITE TO OUT ERROR", "Error while writing to output stream");
        }
    }

    private int deleteDataFromDevice(File[] files) {

        Log.e("DELETE DATA METHOD ", thisAvdPort * 2 + "");
        for (File f : files) {
            Log.e("FILE NAME ", f.getName());
            getContext().deleteFile(f.getName());
        }
        return 1;
    }

    @Override
    public boolean onCreate() {
        /*
         * Calculate the port number that this AVD listens on.
         * It is just a hack that I came up with to get around the networking limitations of AVDs.
         * The explanation is provided in the PA1 spec.
         */
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        thisAvdPort = Integer.parseInt(portStr);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));

        Log.e("MY PORT NUMBER ", "Port : " + thisAvdPort);
        Log.e("MY CALCULATED NUMBER ", "Port : " + myPort);

        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "NodeJoin", myPort);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            /*
             * Log is a good way to debug your code. LogCat prints out all the messages that
             * Log class writes.
             *
             * Please read http://developer.android.com/tools/debugging/debugging-projects.html
             * and http://developer.android.com/tools/debugging/debugging-log.html
             * for more information on debugging.
             */
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }

        return true;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {

        Log.e("DELETE METHOD in ", thisAvdPort * 2 + "");
        Log.e("DELETE KEY ", selection);

        if (predecessor == thisAvdPort * 2 && successor == thisAvdPort * 2) {
            // only 1 device

            Log.e("ONE DEVICE ", "DELETE Method!!!!");
            Log.e("PRED SUCC ", "Pred: " + predecessor + " Succ: " + successor);

            try {
                if (selection.equals("@") || selection.equals("*")) {
                    // delete all values from local device
                    return deleteDataFromDevice(getContext().getFilesDir().listFiles());
                } else {
                    // delete the key val on this device
                    if(getContext().deleteFile(selection))
                        return 1;
                }
            } catch (Exception e) {
                Log.e(TAG, "File not found!");
                return 0;
            }
        } else {
            // more than one device in the ring, search value here
            // if found return, else forward it to the successor
            if (selection.equals("*")) {
                // delete all local data first
                Log.e("*", "ALL files");
                deleteDataFromDevice(getContext().getFilesDir().listFiles());
                //pass the query to successors to delete data
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "deleteAll", myPort);

            } else if (selection.equals("@")) {

                // delete all values from local device
                return deleteDataFromDevice(getContext().getFilesDir().listFiles());

            } else {
                // delete by finding key
                if (keyBelongsToMe(selection, thisAvdPort, predecessor / 2)) {
                    // delete key from here
                    if(getContext().deleteFile(selection))
                        return 1;

                } else {
                    // pass on the value to successor
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", myPort, selection);
                }
            }
        }
        return 1;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {

        String filename = values.get(KEY_FIELD).toString();
        String val = values.get(VALUE_FIELD).toString();

        Log.e("INSERT METHOD in ", thisAvdPort * 2 + "");
        Log.e("INSERT KEY ", filename);
        Log.e("INSERT VALUE ", val);

        Log.e("Predecessor:  ", predecessor + "");
        Log.e("Successor:  ", successor + "");
        Log.e("THIS AVD:  ", thisAvdPort * 2 + "");

        if (predecessor == thisAvdPort * 2 && successor == thisAvdPort * 2) {
            // only 1 device, store the value here

            Log.e("ONE DEVICE ", "1 device only");
            writeToFile(filename, val);

        } else {

            Log.e("MULTIPLE DEVICES ", "multiple devices");
            // more than 1 device in the ring

            if (keyBelongsToMe(filename, thisAvdPort, predecessor / 2)) {
                // insert key here
                writeToFile(filename, val);
            } else {
                // pass on the value to successor
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "insert", myPort, filename, val);
            }
        }
        Log.v("INSERT METHOD ", values.toString());
        return uri;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {

        Cursor matrixCursor = new MatrixCursor(new String[]{KEY_FIELD, VALUE_FIELD});
        Log.e("QUERY METHOD in ", thisAvdPort * 2 + "");
        Log.e("QUERY  ", selection);

        if (selection.equals("*")) {
            if (predecessor == thisAvdPort * 2 && successor == thisAvdPort * 2) {
                // only 1 device

                Log.e("ONE DEVICE ", "Query Method!!!!");
                Log.e("PRED SUCC ", "Pred: " + predecessor + " Succ: " + successor);
                Map<String, String> keyValMap = new LinkedHashMap<String, String>();
                readDataFromDevice(getContext().getFilesDir().listFiles(), keyValMap);
                matrixCursor = getCursorFromMap(keyValMap);

            } else {

                Log.e("MULTIPLE DEVICES ", "Query Method!!!!");
                Log.e("Predecessor:  ", predecessor + "");
                Log.e("Successor:  ", successor + "");
                Log.e("THIS AVD:  ", thisAvdPort * 2 + "");

                // more than one device in the ring, go on adding to the result
                // if found return, else forward it to the successor
                try {
                    Map<String, String> keyValMap = new LinkedHashMap<String, String>();
                    readDataFromDevice(getContext().getFilesDir().listFiles(), keyValMap);
                    // pass on the tempMap to successor
                    Log.e("BEFORE SENDING ", keyValMap.toString());

                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "queryAll", myPort, keyValMap.toString());

                    queryAllResultMap = new LinkedHashMap<String, String>();
                    Object[] mRow = new Object[2];
                    while (true) {
                        if (queryAllResultMap.size() > 0) {
                            queryAllResultMap.remove("size");
                            for (Map.Entry<String, String> entries : queryAllResultMap.entrySet()) {
                                mRow[0] = entries.getKey();
                                mRow[1] = entries.getValue();
                                ((MatrixCursor) matrixCursor).addRow(mRow);
                            }
                            break;
                        }
                    }
                    Log.e("RESULT RECEIVED ", "at initiating device " + thisAvdPort * 2);
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e("ERROR QUERYING ", "");
                }
            }
        } else if (selection.equals("@")) {
            Log.e("@ QUERY", selection);
            // read values from current device
            Map<String, String> keyValMap = new LinkedHashMap<String, String>();
            readDataFromDevice(getContext().getFilesDir().listFiles(), keyValMap);
            matrixCursor = getCursorFromMap(keyValMap);

        } else {

            if (predecessor == thisAvdPort * 2 && successor == thisAvdPort * 2) {
                // only 1 DEVICE
                Map<String, String> keyValMap = new LinkedHashMap<String, String>();
                readDataFromDevice(new File(getContext().getFilesDir(),selection), keyValMap);
                matrixCursor = getCursorFromMap(keyValMap);
                Log.e("ONE DEVICE KEY QUERY", selection);

            } else {
                // multiple devices
                if (keyBelongsToMe(selection, thisAvdPort, predecessor / 2)) {
                    Map<String, String> keyValMap = new LinkedHashMap<String, String>();
                    readDataFromDevice(new File(getContext().getFilesDir(),selection), keyValMap);
                    matrixCursor = getCursorFromMap(keyValMap);

                } else {
                    // key doesn't belong here so pass on
                    returnResultToQueryInitiator = null;
                    // pass on the value to successor
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", myPort, selection);
                    Object[] mRow = new Object[2];
                    while (true) {
                        if (returnResultToQueryInitiator != null) {
                            String splitStr[] = returnResultToQueryInitiator.split("##");
                            mRow[0] = splitStr[0];
                            mRow[1] = splitStr[1];
                            ((MatrixCursor) matrixCursor).addRow(mRow);
                            break;
                        }
                    }
                }
            }
        }
        return matrixCursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private void notifyPredecessorAndSuccessor(String operation, String requestingPort, String routeToPort, String data) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, operation, requestingPort, routeToPort, data);
    }

    private void passInsertQueryToSuccessor(String requestingPort, String key, String val) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "insert", requestingPort, key, val);
    }

    private void passQueryToSuccessor(String requestingPort, String queryKey) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", requestingPort, queryKey);
    }

    private void passQueryResultToInitiator(String requestingPort, String result) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "sendResultToInitiator", requestingPort, result);
    }

    private void passQueryAllToSuccessor(String requestingPort, String partiaResult) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "queryAll", requestingPort, partiaResult);
    }

    private void passDeleteQueryToSuccessor(String requestingPort, String searchKey) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", requestingPort, searchKey);
    }

    private void passDeleteAllToSuccessor(String requestingPort) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "deleteAll", requestingPort);
    }

    /***
     * ServerTask is an AsyncTask that should handle incoming messages. It is created by
     * ServerTask.executeOnExecutor() call in SimpleMessengerActivity.
     *
     * Please make sure you understand how AsyncTask works by reading
     * http://developer.android.com/reference/android/os/AsyncTask.html
     *
     * @author stevko
     *
     */
    private class ServerTask extends AsyncTask<ServerSocket, String, Void> implements Serializable {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            Socket socketConnection;
            String operation = "";
            int requestingPort = 0;

            // Server listens to establish any connections on the socket
            while (true) {
                try {

                    // Server waits for a connection to be established on this socket
                    // Reference: https://developer.android.com/reference/java/net/ServerSocket.html#accept()
                    socketConnection = serverSocket.accept();
                    DataInputStream inputStream = new DataInputStream(socketConnection.getInputStream());

                    // Server reads data from the socket's input stream
                    // Reference: https://developer.android.com/reference/java/io/DataInputStream#readUTF()
                    String clientRequest = inputStream.readUTF();

                    DataOutputStream outputStream;

                    if (clientRequest.startsWith("PRED_SUCC")) {

                        String values[] = clientRequest.split("##");
                        predecessor = Integer.parseInt(values[1]);
                        successor = Integer.parseInt(values[2]);
                        Log.e("PRED SUCC RCVD ", "Node: " + myPort + " Pred: " + predecessor + " Succ: " + successor);

                    } else if (clientRequest.startsWith("READ_RES")) {

                        Log.e("RECEIVED READ_RES at ", thisAvdPort * 2 + "");
                        // return result to query initiator
                        String splitStr[] = clientRequest.split("##");
                        returnResultToQueryInitiator = splitStr[1] + "##" + splitStr[2];

                    } else if (clientRequest.startsWith("QUERY_ALL_RESULT")) {

                        Log.e("RECEIVED QUERY_ALL at ", thisAvdPort * 2 + "");
                        String splitStr[] = clientRequest.split("##");
                        queryAllResultMap = getMapFromString(splitStr[1]);

                    } else if(clientRequest.startsWith("NEW_SUCCESSOR")) {
                        String splitStr[] = clientRequest.split("##");
                        successor = Integer.parseInt(splitStr[1]);

                    } else if(clientRequest.startsWith("NEW_PREDECESSOR")) {
                        String splitStr[] = clientRequest.split("##");
                        predecessor = Integer.parseInt(splitStr[1]);

                    } else {

                        String[] tokens = clientRequest.split("##");
                        operation = tokens[0];
                        requestingPort = Integer.parseInt(tokens[1]);

                        if ("NodeJoin".equals(operation)) {
                            String notifyNewNode = "";
                            Log.e("SERVER SIDE", "Join request rcvd:  " + tokens[1]);

                            // Create new entry for itself
                            RingNode rn = new RingNode();
                            rn.setNodeId(requestingPort);
                            rn.setPredecessor(requestingPort);
                            rn.setSuccessor(requestingPort);
                            avdMap.put(tokens[2], rn);

                            nodeIndexArray = new ArrayList<Integer>();
                            nodeIndexHash = new ArrayList<String>();
                            for (Map.Entry entries : avdMap.entrySet()) {
                                RingNode r = (RingNode) entries.getValue();
                                nodeIndexArray.add(r.getNodeId());
                                nodeIndexHash.add(genHash(String.valueOf(r.getNodeId()/2)));

                                Log.e("MAP", entries.getKey().toString());
                                Log.e("MAP", r.getNodeId() + "  " + r.getPredecessor() + " " + r.getSuccessor());
                            }

                            int x = 0;
                            int avdMapSize = avdMap.size();
                            Log.e("MAP SIZE", " " + avdMapSize);

                            if (avdMapSize > 1) {
                                // At least 1 node present
                                for (Map.Entry entries : avdMap.entrySet()) {
                                    RingNode r = (RingNode) entries.getValue();
                                    Log.e("MAP", r.getNodeId() + "  " + entries.getKey());

                                    int pred = (x + (avdMapSize - 1)) % avdMapSize;
                                    int succ = (x + 1) % avdMapSize;

                                    r.setPredecessor(nodeIndexArray.get(pred));
                                    r.setSuccessor(nodeIndexArray.get(succ));

                                    if (r.getNodeId() == requestingPort) {
                                        notifyNewNode = "PRED_SUCC" + "##" + r.getPredecessor() + "##" + r.getSuccessor();
                                    }

                                    if(r.getNodeId() == AVD0_PORT) {
                                        predecessor = nodeIndexArray.get(pred);
                                        successor = nodeIndexArray.get(succ);
                                    }
                                    x++;
                                    Log.e("PRED ", " " + pred);
                                    Log.e("SUCC ", " " + succ);
                                    Log.e("After Setting pred succ", r.getNodeId() + " " + r.getPredecessor() + " " + r.getSuccessor());
                                }

                                Log.e("MAPPPPPPP ", "SERVER SIDE MAP IN AVD 0");
                                if (avdMap.size() > 0) {
                                    // print ring
                                    int p = 0;
                                    for (Map.Entry e : avdMap.entrySet()) {
                                        RingNode rr = (RingNode) e.getValue();
                                        Log.i(e.getKey() + " " + String.valueOf(rr.getNodeId()), " -->");
                                        Log.i("Pred ", String.valueOf(rr.getPredecessor()) + "  Succ: " + String.valueOf(rr.getSuccessor()));
                                    }
                                }

                                int newNodeIndex = nodeIndexArray.indexOf(requestingPort);
                                int newPred = (newNodeIndex + (avdMapSize - 1)) % avdMapSize;
                                int newSucc = (newNodeIndex + 1) % avdMapSize;

                                Log.e("NOTIFY NEW PRED ", nodeIndexArray.get(newPred)+"");
                                Log.e("NOTIFY NEW SUCC ", nodeIndexArray.get(newSucc)+"");

                                String notifyNewPred = "NEW_SUCCESSOR##" + requestingPort;
                                notifyPredecessorAndSuccessor("notifyAboutNewNode", String.valueOf(thisAvdPort), String.valueOf(nodeIndexArray.get(newPred)), notifyNewPred);

                                String notifyNewSucc = "NEW_PREDECESSOR##" + requestingPort;
                                notifyPredecessorAndSuccessor("notifyAboutNewNode", String.valueOf(thisAvdPort), String.valueOf(nodeIndexArray.get(newSucc)), notifyNewSucc);

                                // notify new node
                                outputStream = new DataOutputStream(socketConnection.getOutputStream());
                                outputStream.writeUTF(notifyNewNode);
                                outputStream.flush();
                            }

                        } else if ("insert".equals(operation)) {

                            String key = tokens[2];
                            String val = tokens[3];

                            if (keyBelongsToMe(key, thisAvdPort, predecessor / 2)) {
                                // insert in current avd
                                Log.e("INSERTING ", "in device  " + thisAvdPort * 2);
                                writeToFile(key, val);
                            } else {
                                // pass insert query to successor
                                Log.e("INSERT QUERY Passing ", "to device  " + successor);
                                passInsertQueryToSuccessor(String.valueOf(requestingPort), key, val);
                            }

                        } else if ("query".equals(operation)) {

                            String queryKey = tokens[2];

                            if (keyBelongsToMe(queryKey, thisAvdPort, predecessor / 2)) {
                                // read value from current avd
                                Map<String, String> keyValMap = new LinkedHashMap<String, String>();
                                readDataFromDevice(new File(getContext().getFilesDir(),queryKey), keyValMap);
                                Log.e("QUERY RESULT ", keyValMap.get(queryKey));
                                String queryResult = "READ_RES##" + queryKey + "##" + keyValMap.get(queryKey);
                                Log.e("SERVER QUERY RES ", keyValMap.get(queryKey));
                                passQueryResultToInitiator(String.valueOf(requestingPort), queryResult);

                            } else {
                                // pass insert query to successor
                                Log.e(" QUERY Passing ", "to device  " + successor);
                                passQueryToSuccessor(String.valueOf(requestingPort), queryKey);
                            }
                        } else if ("queryAll".equals(operation)) {

                            Log.e("TOKENS " , tokens.toString());
                            Log.e("SERVER QUERY ALL ", "Device " + thisAvdPort*2);
                            Log.e("SERVER QUERY ALL INIT ", "Device " + requestingPort);
                            String partialMap = tokens[2];
                            Map<String, String> keyValueMap = getMapFromString(partialMap);

                            if(thisAvdPort*2 != requestingPort) {
                                Log.e("SER QUERYALL PASS ON ", "Current device " + thisAvdPort);
                                // read data and pass the result to successor
                                Map<String, String> srcMap = new LinkedHashMap<String, String>();
                                readDataFromDevice(getContext().getFilesDir().listFiles(), srcMap);
                                // copy values of current avd to result map
                                for(Map.Entry entries:srcMap.entrySet()) {
                                    keyValueMap.put(entries.getKey().toString(), entries.getValue().toString());
                                }
                                passQueryAllToSuccessor(String.valueOf(requestingPort), keyValueMap.toString());
                            } else {
                                Log.e("SERVER  QUERYALL STOP ", "Device rcvd " + thisAvdPort);
                                // finished reading all data, send result to initiator
                                int mapSize = keyValueMap.size();
                                keyValueMap.put("size",String.valueOf(mapSize));
                                queryAllResultMap = keyValueMap;
                            }
                        } else if ("delete".equals(operation)) {
                            String searchKey = tokens[2];
                            if (keyBelongsToMe(searchKey, thisAvdPort, predecessor / 2)) {
                                // insert in current avd
                                Log.e("DELETING ", "from device  " + thisAvdPort * 2);
                                getContext().deleteFile(searchKey);
                            } else {
                                // pass delete query to successor
                                Log.e("DELETE QUERY Passing ", "to device  " + successor);
                                passDeleteQueryToSuccessor(String.valueOf(requestingPort), searchKey);
                            }
                        } else if ("deleteAll".equals(operation)) {

                            if(thisAvdPort*2 != requestingPort) {
                                // delete data and pass delete query to successor
                                deleteDataFromDevice(getContext().getFilesDir().listFiles());
                                passDeleteAllToSuccessor(String.valueOf(requestingPort));
                            }
                        }
                    }
                } catch (IOException e) {
                    Log.e(TAG, "Error reading data from input stream!");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /***
     * ClientTask is an AsyncTask that should send a string over the network.
     * It is created by ClientTask.executeOnExecutor() call whenever OnKeyListener.onKey() detects
     * an enter key press event.
     *
     * @author stevko
     *
     */
    private class ClientTask extends AsyncTask<String, Void, String> {

        @Override
        protected String doInBackground(String... msgs) {

            String operation = msgs[0];
            String operationRequestedByPort = msgs[1];

            if (operation.equals("NodeJoin")) {
                try {

                    String hash = genHash(String.valueOf(Integer.parseInt(operationRequestedByPort) / 2));

                    if (thisAvdPort * 2 == AVD0_PORT) {

                        Log.e("CLIENT ONE DEVICE " , "device: " + thisAvdPort*2);
                        // Create new entry for itself
                        RingNode rn = new RingNode();
                        rn.setNodeId(thisAvdPort * 2);
                        rn.setPredecessor(thisAvdPort * 2);
                        rn.setSuccessor(thisAvdPort * 2);
                        avdMap.put(hash, rn);

                        predecessor = AVD0_PORT;
                        successor = AVD0_PORT;

                    } else {
                        // Some other node joining
                        String msgToSend = operation + "##" + operationRequestedByPort + "##" + hash;
                        Log.e(TAG, "CLIENT JOIN REQUEST  " + msgToSend);

                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                AVD0_PORT);
                        DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
                        outStream.writeUTF(msgToSend);

                        DataInputStream inStream = new DataInputStream(socket.getInputStream());
                        String msg = inStream.readUTF();
                        Log.e("MSG FROM AVD0 JOIN", msg);

                        String values[] = msg.split("##");
                        predecessor = Integer.parseInt(values[1]);
                        successor = Integer.parseInt(values[2]);
                        Log.e("PRED SUCC RCVD ", "Node: " + myPort + " Pred: " + predecessor + " Succ: " + successor);
                    }

                } catch (Exception e) {

                    e.printStackTrace();
                    Log.e("AVD0 NOT PRESENT", "Only 1 device up " + myPort);
                    predecessor = Integer.parseInt(myPort);
                    successor = Integer.parseInt(myPort);
                    Log.i("DEVICE PRESENT ", "Device: " + myPort + "  Pred: " + predecessor + " Succ: " + successor);
                }

            } else if (operation.equals("insert")) {

                Log.e("CLIENT INSERT from", thisAvdPort * 2 + "");
                // pass the insert query to successor
                String key = msgs[2];
                String val = msgs[3];

                Log.e(TAG, "CLIENT Insert key " + key);
                String passInsertQuery = operation + "##" + operationRequestedByPort + "##" + key + "##" + val;
                writeToOutPutStream(passInsertQuery, successor);

            } else if (operation.equals("query")) {

                String queryKey = msgs[2];
                Log.e(TAG, "CLIENT Actual Query " + queryKey + "  at avd " + thisAvdPort * 2);
                String passInsertQuery = operation + "##" + operationRequestedByPort + "##" + queryKey;
                writeToOutPutStream(passInsertQuery, successor);

            } else if (operation.equals("queryAll")) {

                // Query *
                Log.e("CLIENT QUERY ALL * from", thisAvdPort * 2 + "");
                String partialResultMap = msgs[2];
                Log.i("CLIENT PARTIAL MAP ", partialResultMap);
                String passQueryAll = operation + "##" + operationRequestedByPort + "##" + partialResultMap;
                Log.e("CLIENT PASSING TO ", successor+"");
                writeToOutPutStream(passQueryAll, successor);

            } else if (operation.equals("delete")) {

                Log.e("DELETE QUERY ", thisAvdPort * 2 + "");
                // pass the delete query to successor
                String key = msgs[2];
                String passDeleteQuery = operation + "##" + operationRequestedByPort + "##" + key;
                writeToOutPutStream(passDeleteQuery, successor);

            } else if (operation.equals("deleteAll")) {

                Log.e("DELETE ALL QUERY ", thisAvdPort * 2 + "");
                String passDeleteAllQuery = operation + "##" + operationRequestedByPort;
                writeToOutPutStream(passDeleteAllQuery, successor);

            } else if(operation.equals("notifyAboutNewNode")) {
                int routeToPort = Integer.parseInt(msgs[2]);
                String data = msgs[3];
                writeToOutPutStream(data, routeToPort);
                writeToOutPutStream(data, routeToPort);

            } else if(operation.equals("sendResultToInitiator")) {
                String result = msgs[2];
                writeToOutPutStream(result, Integer.parseInt(operationRequestedByPort));
            }
            return null;
        }
    }
}
