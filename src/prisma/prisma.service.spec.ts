import { PrismaService } from './prisma.service';

describe('PrismaService', () => {
  let prismaService: PrismaService;

  beforeEach(() => {
    prismaService = new PrismaService();
  });

  describe('init', () => {
    it('should init prisma service', () => {
      expect(prismaService).toBeDefined();
    });

    it('should connect to database', async () => {
      await prismaService.onModuleInit();
      expect(prismaService.$connect()).toBeDefined();
    });
  });
});
