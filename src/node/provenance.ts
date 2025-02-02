import { Provenance } from "../common/provenance";
import { UploadReceipt } from "../common/types";
import { CreateAndUploadOptions } from "../common/types";
import NodeIrys from "./irys";

export class NodeProvenance extends Provenance {
  declare irys: NodeIrys;
  constructor(irys: NodeIrys) {
    super(irys);
  }

  public async uploadFile(path: string, opts?: CreateAndUploadOptions): Promise<UploadReceipt> {
    return this.irys.uploadFile(path, { ...opts, upload: { ...opts?.upload, getReceiptSignature: true } }) as Promise<UploadReceipt>;
  }

  public async uploadFolder(
    path: string,
    {
      batchSize = 10,
      keepDeleted = true,
      indexFile,
      interactivePreflight,
      logFunction,
      manifestTags,
      itemOptions,
    }: {
      batchSize: number;
      keepDeleted: boolean;
      indexFile?: string;
      interactivePreflight?: boolean;
      logFunction?: (log: string) => Promise<void>;
      manifestTags?: { name: string; value: string }[];
      itemOptions?: CreateAndUploadOptions;
    } = { batchSize: 10, keepDeleted: true },
  ): Promise<UploadReceipt & { receipts: Map<string, UploadReceipt> }> {
    return this.irys.uploadFolder(path, {
      batchSize,
      keepDeleted,
      indexFile,
      interactivePreflight,
      logFunction,
      manifestTags,
      itemOptions: { ...itemOptions, upload: { ...itemOptions?.upload, getReceiptSignature: true } },
    }) as Promise<UploadReceipt & { receipts: Map<string, UploadReceipt> }>;
  }
}
