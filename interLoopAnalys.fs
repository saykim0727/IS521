 (*
   B2R2 - the Next-Generation Reversing Platform

   Author: Hyunki Kim <saykim0727@kaist.ac.kr>

   Copyright (c) SoftSec Lab. @ KAIST, since 2016

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
 *)

module B2R2.VSA.LoopAnalysis

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.BinGraph

let getAddr (v:Vertex<SSAVertexData>) =
  let a,b = v.VData.IRVertexData.GetPpoint ()
  if a then fst b else 0UL

let getTail cycleList (v: Vertex<_>) =
  cycleList |> List.filter (fun elem -> List.contains (v.GetID()) elem.Tail)

let addCycleBody (v: Vertex<_>) cycleList result =
  let cycle = getTail cycleList v
  if List.length cycle <> 1 then failwith "here!"
  else
    let cycle = List.head cycle
    let body = cycle.Body
    List.append body result |> List.distinct

// To solve infinit loop of nestedLoop
let isTail (v:Vertex<_>) cycleList =
  let cycle = getTail cycleList v
  if List.isEmpty cycle then false else true

let isFuncCall (pred:Vertex<_>) (succ:Vertex<_>) (cfg: DiGraph<_, _>) =
  let edge = cfg.FindEdge pred succ
  match edge with
  | CallEdge -> true
  | _ -> false

let rec findLoopBody (head:Vertex<SSAVertexData>) (v:Vertex<SSAVertexData>)
                      succ result cycleList cfg =
  if v = head then List.append [(v.GetID())] result |> List.distinct
  elif List.contains (v.GetID()) result then result
  elif isTail v cycleList then addCycleBody v cycleList result
  elif isFuncCall v succ cfg then result
  else
    let result = List.append [(v.GetID())] result
    let main acc (pred: Vertex<_>) =
      let data = findLoopBody head pred v acc cycleList cfg
      List.append data acc |> List.distinct
    if List.isEmpty v.Preds then failwithf "%A" result
    else v.Preds |> List.fold main result

let getLoopEdge (head:Vertex<_>) bblList (cfg: DiGraph<_, _>) =
  let index = bblList |> List.findIndex (fun elem -> elem = head)
  let succ = if index = 0 then head else bblList.[(index-1)]
  cfg.FindEdge head succ

let mergeCycle loop1 loop2 cycleList =
  let head = loop1.Head
  let tail = List.append loop1.Tail loop2.Tail
  let edge =
    if loop1.BackEdge = FallThroughEdge ||
      loop1.BackEdge = JmpEdge then loop2.BackEdge
    else loop1.BackEdge
  let body = List.append loop1.Body loop2.Body |> List.distinct
  let cycleList = cycleList |> List.filter (fun elem -> elem.Head <> head)
  let cycle = LoopContext.init head tail edge body
  List.append [cycle] cycleList

let findSameHead cycle cycleList =
  let aList = cycleList |> List.filter (fun elem -> elem.Head = cycle.Head)
  if List.isEmpty aList then List.append [cycle] cycleList
  else
    if List.length aList <> 1 then failwith "!!"
    else mergeCycle (List.head aList) cycle cycleList

let handleLoop (head:Vertex<_>) (tail:Vertex<_>) cycleList cfg edge =
  let body = findLoopBody head tail head [] cycleList cfg
  let cycle = LoopContext.init (head.GetID()) [(tail.GetID())] edge body
  findSameHead cycle cycleList

let rec handleVertex (v:Vertex<_>) pred bblList cycleList ssacfg =
  if List.contains v bblList then
    getLoopEdge v bblList ssacfg |> handleLoop v pred cycleList ssacfg
  elif List.length bblList > 0 && isFuncCall pred v ssacfg then cycleList
  elif v.IsVisited then cycleList
  else
    v.Visit()
    let bblList = List.append [v] bblList
    let handleSucc acc (succ: Vertex<_>) =
      handleVertex succ v bblList acc ssacfg
    if List.isEmpty v.Succs then cycleList
    else v.Succs |> List.fold handleSucc cycleList

let analyzeLoop (f: Function) cycleList =
  let cfg = f.SSACFG
  let root = cfg.GetRoot ()
  let result = handleVertex root root [] cycleList cfg
  result

let rec analyzeFuncs (func: Vertex<Function>) funcList =
  let analyzeFunc acc (elem: Vertex<_>) =
    if List.contains (elem.VData) acc then acc
    else analyzeFuncs elem acc
  let funcList = List.append [func.VData] funcList
  func.Succs |> List.fold analyzeFunc funcList


let main func =
  let funcList = analyzeFuncs func []
  printfn "%A" (List.length funcList)
  funcList |> List.fold (fun acc elem -> analyzeLoop elem acc ) []



